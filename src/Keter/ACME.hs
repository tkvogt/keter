{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TupleSections #-}

-- | ACME v2 (Let's Encrypt) automatic certificate management.
--
-- This module implements RFC 8555 (ACME) to automatically obtain and renew
-- TLS certificates from Let's Encrypt (or any compatible ACME CA).
--
-- Usage in @keter-config.yaml@:
--
-- > acme:
-- >   email: admin@example.com
--
-- Then in bundle stanzas:
--
-- > ssl: acme
module Keter.ACME
    ( AcmeState
    , defaultAcmeDirectory
    , initAcme
    , getOrRequestCert
    , renewExpiring
    , certDirFor
    ) where

import Control.Concurrent (threadDelay)
import Control.Exception (Exception, SomeException, bracket_, throwIO, try)
import Control.Monad (forM_, unless, when)
import Crypto.Hash (SHA256 (..), hashWith)
import Crypto.PubKey.RSA qualified as RSA
import Crypto.PubKey.RSA.PKCS15 qualified as PKCS15
import Data.ASN1.BinaryEncoding (DER (..))
import Data.ASN1.BitArray (toBitArray)
import Data.ASN1.Encoding (decodeASN1', encodeASN1')
import Data.ASN1.Types
import Data.Aeson ((.=))
import Data.Aeson qualified as Aeson
import Data.Aeson.Key qualified as AKey
import Data.Aeson.KeyMap qualified as AKM
import Data.ByteArray (convert)
import Data.ByteString (ByteString)
import Data.ByteString qualified as BS
import Data.ByteString.Base64.URL qualified as B64URL
import Data.ByteString.Char8 qualified as BS8
import Data.ByteString.Lazy qualified as LBS
import Data.IORef
import Data.List (find, intercalate)
import Data.Map.Strict (Map)
import Data.Map.Strict qualified as Map
import Data.Maybe (fromMaybe, listToMaybe, mapMaybe)
import Data.PEM (PEM (..), pemContent, pemParseBS, pemWriteBS)
import Data.Text (Text)
import Data.Text qualified as T
import Data.Text.Encoding (decodeUtf8, encodeUtf8)
import Data.Time
import Data.Typeable (Typeable)
import Keter.Config.V10 (AcmeConfig (..))
import Network.HTTP.Client
import Network.HTTP.Client.TLS (newTlsManager)
import Network.TLS qualified as TLS
import System.Directory
    ( createDirectoryIfMissing
    , doesDirectoryExist
    , doesFileExist
    , listDirectory
    )
import System.FilePath ((</>))
import System.IO (hPutStrLn, stderr)
import Time.Types qualified as H

-- ---------------------------------------------------------------------------
-- Runtime state
-- ---------------------------------------------------------------------------

data AcmeDirectory = AcmeDirectory
    { dirNewNonce   :: !Text
    , dirNewAccount :: !Text
    , dirNewOrder   :: !Text
    }

-- | The Let's Encrypt v2 production directory URL.
defaultAcmeDirectory :: Text
defaultAcmeDirectory = "https://acme-v02.api.letsencrypt.org/directory"

-- | Mutable ACME manager state.  Create with 'initAcme'.
data AcmeState = AcmeState
    { asConfig     :: !AcmeConfig
    , asAccountKey :: !RSA.PrivateKey
    , asAccountUrl :: !(IORef (Maybe Text))
    -- ^ Cached account URL; 'Nothing' until first registration.
    , asManager    :: !Manager
    -- ^ HTTP manager for ACME requests (TLS-enabled).
    , asChallenges :: !(IORef (Map ByteString ByteString))
    -- ^ Active HTTP-01 challenges: token → key-authorisation.
    --   Shared with 'Keter.Proxy' so challenges can be served on port 80.
    }

data AcmeException = AcmeException String
    deriving (Show, Typeable)
instance Exception AcmeException

throwAcme :: String -> IO a
throwAcme = throwIO . AcmeException

-- ---------------------------------------------------------------------------
-- Initialisation
-- ---------------------------------------------------------------------------

-- | Initialise the ACME manager.  Loads or generates the account key from
--   disk, and re-uses any previously registered account URL.
--
--   The @challengeMap@ 'IORef' is shared with the HTTP proxy so that
--   @\/.well-known\/acme-challenge\/\<token\>@ requests can be answered.
initAcme :: AcmeConfig -> IORef (Map ByteString ByteString) -> IO AcmeState
initAcme cfg challenges = do
    let acmeDir = acmeCertDir cfg
    createDirectoryIfMissing True acmeDir
    createDirectoryIfMissing True (acmeDir </> "certs")

    key <- loadOrCreateAccountKey (acmeDir </> "account.pem")
    mgr <- newTlsManager

    urlRef <- newIORef Nothing
    let urlFile = acmeDir </> "account-url.txt"
    exists <- doesFileExist urlFile
    when exists $ do
        url <- T.strip . decodeUtf8 <$> BS.readFile urlFile
        unless (T.null url) $ writeIORef urlRef (Just url)

    return AcmeState
        { asConfig     = cfg
        , asAccountKey = key
        , asAccountUrl = urlRef
        , asManager    = mgr
        , asChallenges = challenges
        }

-- ---------------------------------------------------------------------------
-- Public API
-- ---------------------------------------------------------------------------

-- | Load a certificate from disk if it is still valid (not expiring within
--   30 days), or request a fresh one from the ACME CA.
--
--   Returns 'mempty' on failure (keter continues without ACME for this host).
getOrRequestCert :: AcmeState
                 -> Text    -- ^ Primary domain (used as the cert storage key)
                 -> [Text]  -- ^ All domains to include as SANs
                 -> IO TLS.Credentials
getOrRequestCert st primaryDomain domains = do
    result <- try $ getOrRequestCert' st primaryDomain domains
    case result of
        Right creds -> return creds
        Left (AcmeException msg) -> do
            hPutStrLn stderr $
                "[ACME] certificate request failed for " ++ T.unpack primaryDomain
                ++ ": " ++ msg
            return mempty

-- | Scan the certificate store and renew any certificates expiring within
--   30 days.  Returns @(primaryDomain, newCredentials)@ for each renewed cert
--   so the caller can update the TLS credentials in the host manager.
renewExpiring :: AcmeState -> IO [(Text, TLS.Credentials)]
renewExpiring st = do
    let certsDir = acmeCertDir (asConfig st) </> "certs"
    dirExists <- doesDirectoryExist certsDir
    if not dirExists
        then return []
        else do
            entries <- listDirectory certsDir
            fmap (mapMaybe id) $ mapM (tryRenew certsDir) entries
  where
    tryRenew certsDir entry = do
        let certFile = certsDir </> entry </> "cert.pem"
            keyFile  = certsDir </> entry </> "key.pem"
            domsFile = certsDir </> entry </> "domains"
        allExist <- and <$> mapM doesFileExist [certFile, keyFile, domsFile]
        if not allExist then return Nothing else do
            needsRenewal <- certNeedsRenewal certFile
            if not needsRenewal then return Nothing else do
                domainsRaw <- lines <$> readFile domsFile
                let domains = map T.pack domainsRaw
                case domains of
                    [] -> return Nothing
                    (primaryDomain:_) -> do
                        result <- try $ requestAndCacheCert st primaryDomain domains
                        case result of
                            Left (AcmeException msg) -> do
                                hPutStrLn stderr $
                                    "[ACME] renewal failed for "
                                    ++ T.unpack primaryDomain ++ ": " ++ msg
                                return Nothing
                            Right creds ->
                                return $ Just (primaryDomain, creds)

-- ---------------------------------------------------------------------------
-- Internal helpers: high-level flow
-- ---------------------------------------------------------------------------

getOrRequestCert' :: AcmeState -> Text -> [Text] -> IO TLS.Credentials
getOrRequestCert' st primaryDomain domains = do
    let certFile = certPath st primaryDomain "cert.pem"
        keyFile  = certPath st primaryDomain "key.pem"
    hasCert <- doesFileExist certFile
    if hasCert
        then do
            needsRenewal <- certNeedsRenewal certFile
            if needsRenewal
                then requestAndCacheCert st primaryDomain domains
                else loadCertCreds certFile keyFile
        else requestAndCacheCert st primaryDomain domains

requestAndCacheCert :: AcmeState -> Text -> [Text] -> IO TLS.Credentials
requestAndCacheCert st primaryDomain domains = do
    logInfo $ "Requesting certificate for: "
              ++ intercalate ", " (map T.unpack domains)

    dir        <- fetchDirectory (asManager st) (acmeDirectory $ asConfig st)
    accountUrl <- ensureAccount st dir

    -- 1. Create an order for all requested domains
    let orderPayload = Aeson.object
            [ "identifiers" .= map (\d -> Aeson.object
                    [ "type"  .= ("dns" :: Text)
                    , "value" .= d
                    ]) domains
            ]
    orderResp <- acmePost st dir accountUrl (dirNewOrder dir) (Just orderPayload)
    orderJson <- decodeBody "order" (responseBody orderResp)

    finalizeUrl <- maybe (throwAcme "No finalize URL in order") return
                         (lookupText "finalize" orderJson)
    authUrls    <- maybe (throwAcme "No authorizations in order") return
                         (lookupArray "authorizations" orderJson)

    -- 2. Complete HTTP-01 challenge for each domain authorization
    forM_ authUrls $ \authVal ->
        case authVal of
            Aeson.String authUrl ->
                completeHTTP01Challenge st dir accountUrl authUrl
            _ -> throwAcme "Authorization entry is not a URL string"

    -- 3. Generate a fresh RSA key for the certificate and build a CSR
    (certPub, certPriv) <- RSA.generate 256 65537
    csrDer <- generateCSR certPriv certPub (map T.unpack domains)

    -- 4. Finalize the order
    let finalizePayload = Aeson.object
            [ "csr" .= decodeUtf8 (b64url csrDer) ]
    _ <- acmePost st dir accountUrl finalizeUrl (Just finalizePayload)

    -- 5. Poll order until the CA issues the certificate
    orderUrl <- case lookup "Location" (responseHeaders orderResp) of
        Just loc -> return (decodeUtf8 loc)
        Nothing  -> throwAcme "No Location header in order response"
    certUrl <- pollOrderForCertUrl st dir accountUrl orderUrl

    -- 6. Download the certificate chain (PEM)
    certChainPem <- downloadCertificate (asManager st) certUrl

    -- 7. Save certificate and private key to disk
    let certFile = certPath st primaryDomain "cert.pem"
        keyFile  = certPath st primaryDomain "key.pem"
        domsFile = certPath st primaryDomain "domains"
    createDirectoryIfMissing True (certDirFor st primaryDomain)
    BS.writeFile certFile certChainPem
    BS.writeFile keyFile  (rsaPrivKeyToPEM certPriv)
    writeFile    domsFile (unlines (map T.unpack domains))

    logInfo $ "Certificate saved for: " ++ T.unpack primaryDomain
    loadCertCreds certFile keyFile

loadCertCreds :: FilePath -> FilePath -> IO TLS.Credentials
loadCertCreds certFile keyFile = do
    result <- TLS.credentialLoadX509Chain certFile [] keyFile
    case result of
        Left err   -> throwAcme $ "Failed to load certificate: " ++ err
        Right cred -> return $ TLS.Credentials [cred]

certDirFor :: AcmeState -> Text -> FilePath
certDirFor st primaryDomain =
    acmeCertDir (asConfig st) </> "certs" </> sanitizeDomain primaryDomain

certPath :: AcmeState -> Text -> FilePath -> FilePath
certPath st primaryDomain filename = certDirFor st primaryDomain </> filename

-- ---------------------------------------------------------------------------
-- Certificate expiry checking
-- ---------------------------------------------------------------------------

-- | Returns 'True' if the certificate at the given path expires within 30 days
--   (or cannot be parsed).
certNeedsRenewal :: FilePath -> IO Bool
certNeedsRenewal certFile = do
    mExpiry <- getCertExpiry certFile
    case mExpiry of
        Nothing     -> return True
        Just expiry -> do
            now <- getCurrentTime
            let renewThreshold = addUTCTime (30 * nominalDay) now
            return (expiry <= renewThreshold)

-- | Parse the @notAfter@ validity date from a PEM certificate file.
getCertExpiry :: FilePath -> IO (Maybe UTCTime)
getCertExpiry certFile = do
    result <- try (BS.readFile certFile) :: IO (Either SomeException ByteString)
    case result of
        Left _   -> return Nothing
        Right bs ->
            case pemParseBS bs of
                Left _      -> return Nothing
                Right []    -> return Nothing
                Right (p:_) ->
                    case decodeASN1' DER (pemContent p) of
                        Left _     -> return Nothing
                        Right asn1 -> return (findNotAfter asn1)

-- | Walk the flat ASN.1 list and return the second time value found inside a
--   SEQUENCE that contains two consecutive time values (the validity block).
findNotAfter :: [ASN1] -> Maybe UTCTime
findNotAfter = go
  where
    go [] = Nothing
    go (Start Sequence : t1 : t2 : End Sequence : _rest)
        | isTime t1 && isTime t2 = Just (asn1ToUTC t2)
    go (_ : rest) = go rest

    isTime (ASN1Time _ _ _) = True
    isTime _                = False

    asn1ToUTC (ASN1Time _ dt mbTZ) = datetimeToUTC dt mbTZ
    asn1ToUTC _                    = error "ACME.findNotAfter: impossible"

datetimeToUTC :: H.DateTime -> Maybe H.TimezoneOffset -> UTCTime
datetimeToUTC dt mbTZ =
    let d = H.dtDate dt
        t = H.dtTime dt
        day = fromGregorian
                (fromIntegral (H.dateYear d))
                (monthNum (H.dateMonth d))
                (H.dateDay d)
        secs = fromIntegral (H.todHour t) * 3600
             + fromIntegral (H.todMin t) * 60
             + fromIntegral (H.todSec t)
             - fromIntegral (maybe 0 H.timezoneOffsetToMinutes mbTZ) * 60
    in UTCTime day (secondsToDiffTime secs)

monthNum :: H.Month -> Int
monthNum H.January   = 1;  monthNum H.February  = 2;  monthNum H.March     = 3
monthNum H.April     = 4;  monthNum H.May       = 5;  monthNum H.June      = 6
monthNum H.July      = 7;  monthNum H.August    = 8;  monthNum H.September = 9
monthNum H.October   = 10; monthNum H.November  = 11; monthNum H.December  = 12

-- ---------------------------------------------------------------------------
-- Internal helpers: ACME protocol
-- ---------------------------------------------------------------------------

fetchDirectory :: Manager -> Text -> IO AcmeDirectory
fetchDirectory mgr url = do
    req  <- parseRequest (T.unpack url)
    resp <- httpLbs req { requestHeaders = [("Accept", "application/json")] } mgr
    val  <- decodeBody "directory" (responseBody resp)
    newNonce   <- maybe (throwAcme "directory: missing newNonce")   return
                        (lookupText "newNonce"   val)
    newAccount <- maybe (throwAcme "directory: missing newAccount") return
                        (lookupText "newAccount" val)
    newOrder   <- maybe (throwAcme "directory: missing newOrder")   return
                        (lookupText "newOrder"   val)
    return AcmeDirectory
        { dirNewNonce   = newNonce
        , dirNewAccount = newAccount
        , dirNewOrder   = newOrder
        }

fetchNonce :: Manager -> Text -> IO Text
fetchNonce mgr newNonceUrl = do
    req  <- parseRequest (T.unpack newNonceUrl)
    resp <- httpLbs req { method = "HEAD" } mgr
    case lookup "Replay-Nonce" (responseHeaders resp) of
        Nothing    -> throwAcme "ACME server returned no Replay-Nonce"
        Just nonce -> return (decodeUtf8 nonce)

-- | Ensure an ACME account exists and return its URL.  Caches the URL in
--   memory and on disk to avoid repeated registrations.
ensureAccount :: AcmeState -> AcmeDirectory -> IO Text
ensureAccount st dir = do
    mUrl <- readIORef (asAccountUrl st)
    case mUrl of
        Just url -> return url
        Nothing  -> do
            let payload = Aeson.object
                    [ "termsOfServiceAgreed" .= True
                    , "contact" .= ["mailto:" <> acmeEmail (asConfig st) :: Text]
                    ]
            resp <- acmePost' st dir Nothing (dirNewAccount dir) (Just payload)
            url  <- case lookup "Location" (responseHeaders resp) of
                Nothing  -> throwAcme "No Location header in account response"
                Just loc -> return (decodeUtf8 loc)
            writeIORef (asAccountUrl st) (Just url)
            BS.writeFile (acmeCertDir (asConfig st) </> "account-url.txt")
                         (encodeUtf8 url)
            logInfo $ "ACME account registered: " ++ T.unpack url
            return url

-- | POST to an ACME URL, signing with the account key (kid header).
acmePost :: AcmeState -> AcmeDirectory -> Text -> Text -> Maybe Aeson.Value
         -> IO (Response LBS.ByteString)
acmePost st dir accountUrl = acmePost' st dir (Just accountUrl)

-- | POST to an ACME URL.  When @mAccountUrl@ is 'Nothing', embed the JWK
--   in the header (for @newAccount@); otherwise use the @kid@ form.
acmePost' :: AcmeState -> AcmeDirectory -> Maybe Text -> Text -> Maybe Aeson.Value
          -> IO (Response LBS.ByteString)
acmePost' st dir mAccountUrl url mPayload = do
    nonce <- fetchNonce (asManager st) (dirNewNonce dir)
    jws   <- makeJWS (asAccountKey st) nonce url mAccountUrl mPayload
    req   <- parseRequest (T.unpack url)
    let req' = req
            { method         = "POST"
            , requestBody    = RequestBodyLBS (Aeson.encode jws)
            , requestHeaders =
                [ ("Content-Type", "application/jose+json")
                , ("Accept",       "application/json")
                ]
            }
    httpLbs req' (asManager st)

-- | Obtain and serve the HTTP-01 challenge for one authorization URL.
completeHTTP01Challenge :: AcmeState -> AcmeDirectory -> Text -> Text -> IO ()
completeHTTP01Challenge st dir accountUrl authUrl = do
    authResp <- acmePost st dir accountUrl authUrl Nothing  -- POST-as-GET
    authJson <- decodeBody "authorization" (responseBody authResp)

    let challenges = fromMaybe [] (lookupArray "challenges" authJson)
        mChallenge = find (\c -> lookupText "type" c == Just "http-01") challenges
    challenge <- maybe (throwAcme "No HTTP-01 challenge in authorization") return mChallenge

    token      <- maybe (throwAcme "Challenge missing token") return
                        (lookupText "token" challenge)
    challengeUrl <- maybe (throwAcme "Challenge missing url") return
                          (lookupText "url" challenge)

    let keyAuth   = token <> "." <> decodeUtf8 (jwkThumbprint (RSA.private_pub (asAccountKey st)))
        tokenBS   = encodeUtf8 token
        keyAuthBS = encodeUtf8 keyAuth

    -- Insert challenge into shared map; proxy serves it; remove when done.
    bracket_
        (modifyIORef' (asChallenges st) (Map.insert tokenBS keyAuthBS))
        (modifyIORef' (asChallenges st) (Map.delete tokenBS))
        $ do
            -- Notify CA that the challenge is ready
            _ <- acmePost st dir accountUrl challengeUrl (Just (Aeson.object []))
            pollAuthorization st dir accountUrl authUrl

-- | Poll an authorization URL until it is @valid@ (or throw on @invalid@).
pollAuthorization :: AcmeState -> AcmeDirectory -> Text -> Text -> IO ()
pollAuthorization st dir accountUrl authUrl = go (1 :: Int)
  where
    go attempt = do
        when (attempt > 20) $ throwAcme "Timed out waiting for ACME authorization"
        threadDelay (min (attempt * 1000000) 8000000)
        resp <- acmePost st dir accountUrl authUrl Nothing
        val  <- decodeBody "authorization-poll" (responseBody resp)
        case lookupText "status" val of
            Just "valid"   -> return ()
            Just "invalid" -> throwAcme $
                "Authorization invalid: "
                ++ maybe "unknown reason" T.unpack (lookupText "problem" val)
            _              -> go (attempt + 1)

-- | Poll an order URL until it is @valid@ and return the certificate URL.
pollOrderForCertUrl :: AcmeState -> AcmeDirectory -> Text -> Text -> IO Text
pollOrderForCertUrl st dir accountUrl orderUrl = go (1 :: Int)
  where
    go attempt = do
        when (attempt > 20) $ throwAcme "Timed out waiting for ACME order to become valid"
        threadDelay (min (attempt * 1000000) 8000000)
        resp <- acmePost st dir accountUrl orderUrl Nothing
        val  <- decodeBody "order-poll" (responseBody resp)
        case lookupText "status" val of
            Just "valid"   ->
                maybe (throwAcme "Order valid but no certificate URL") return
                      (lookupText "certificate" val)
            Just "invalid" -> throwAcme "ACME order became invalid"
            _              -> go (attempt + 1)

downloadCertificate :: Manager -> Text -> IO ByteString
downloadCertificate mgr url = do
    req  <- parseRequest (T.unpack url)
    resp <- httpLbs req
                { requestHeaders = [("Accept", "application/pem-certificate-chain")] }
                mgr
    let body = LBS.toStrict (responseBody resp)
    when (BS.null body) $ throwAcme "Empty certificate download"
    return body

-- ---------------------------------------------------------------------------
-- JWS (JSON Web Signature) — RFC 7515 / RFC 7518
-- ---------------------------------------------------------------------------

makeJWS :: RSA.PrivateKey
        -> Text              -- ^ Nonce
        -> Text              -- ^ Request URL
        -> Maybe Text        -- ^ Account URL (Nothing → embed JWK; Just → kid)
        -> Maybe Aeson.Value -- ^ Payload (Nothing = POST-as-GET = empty string)
        -> IO Aeson.Value
makeJWS privKey nonce url mAccountUrl mPayload = do
    let pub = RSA.private_pub privKey
        headerObj = case mAccountUrl of
            Nothing ->
                Aeson.object
                    [ "alg"   .= ("RS256" :: Text)
                    , "jwk"   .= rsaPublicKeyToJWK pub
                    , "nonce" .= nonce
                    , "url"   .= url
                    ]
            Just accountUrl ->
                Aeson.object
                    [ "alg"   .= ("RS256" :: Text)
                    , "kid"   .= accountUrl
                    , "nonce" .= nonce
                    , "url"   .= url
                    ]
        protected = b64url (LBS.toStrict (Aeson.encode headerObj))
        payload   = case mPayload of
            Nothing -> ""            -- POST-as-GET: empty string payload
            Just v  -> b64url (LBS.toStrict (Aeson.encode v))
        sigInput  = protected <> "." <> payload
    sig <- signRS256 privKey sigInput
    return $ Aeson.object
        [ "protected" .= decodeUtf8 protected
        , "payload"   .= decodeUtf8 payload
        , "signature" .= decodeUtf8 (b64url sig)
        ]

rsaPublicKeyToJWK :: RSA.PublicKey -> Aeson.Value
rsaPublicKeyToJWK pub = Aeson.object
    [ "kty" .= ("RSA" :: Text)
    , "n"   .= decodeUtf8 (b64url (integerToBS (RSA.public_n pub)))
    , "e"   .= decodeUtf8 (b64url (integerToBS (RSA.public_e pub)))
    ]

-- | Canonical JWK (keys sorted lexicographically) for thumbprint (RFC 7638).
canonicalJWK :: RSA.PublicKey -> ByteString
canonicalJWK pub = LBS.toStrict $ Aeson.encode $ Aeson.object
    [ "e"   .= decodeUtf8 (b64url (integerToBS (RSA.public_e pub)))
    , "kty" .= ("RSA" :: Text)
    , "n"   .= decodeUtf8 (b64url (integerToBS (RSA.public_n pub)))
    ]

jwkThumbprint :: RSA.PublicKey -> ByteString
jwkThumbprint pub = b64url (sha256bs (canonicalJWK pub))

-- ---------------------------------------------------------------------------
-- CSR (PKCS#10) generation — RFC 2986
-- ---------------------------------------------------------------------------

-- | Build and sign a DER-encoded PKCS#10 CSR covering the given domains.
generateCSR :: RSA.PrivateKey -> RSA.PublicKey -> [String] -> IO ByteString
generateCSR privKey pubKey domains = do
    let certReqInfoASN1 = buildCertReqInfo pubKey domains
        certReqInfoDER  = encodeASN1' DER certReqInfoASN1
    sig <- signRS256 privKey certReqInfoDER
    let csrASN1 =
            [ Start Sequence ]      -- CertificationRequest
            ++ certReqInfoASN1      -- CertificationRequestInfo (inline)
            ++
            [ Start Sequence        -- AlgorithmIdentifier: sha256WithRSAEncryption
            , OID [1,2,840,113549,1,1,11]
            , Null
            , End Sequence
            , BitString (toBitArray sig 0)
            , End Sequence
            ]
    return $ encodeASN1' DER csrASN1

buildCertReqInfo :: RSA.PublicKey -> [String] -> [ASN1]
buildCertReqInfo pubKey domains =
    [ Start Sequence  -- CertificationRequestInfo
    , IntVal 0        -- version (0 = v1)
    , Start Sequence  -- subject (empty; ACME fills it)
    , End Sequence
    ]
    ++ subjectPublicKeyInfo pubKey
    ++
    [ Start (Container Context 0) ]   -- attributes [0] IMPLICIT
    ++ extensionRequestAttr domains
    ++
    [ End (Container Context 0)
    , End Sequence
    ]

subjectPublicKeyInfo :: RSA.PublicKey -> [ASN1]
subjectPublicKeyInfo pub =
    [ Start Sequence
    , Start Sequence               -- AlgorithmIdentifier
    , OID [1,2,840,113549,1,1,1]  -- rsaEncryption
    , Null
    , End Sequence
    , BitString (toBitArray rsaPubKeyDER 0)
    , End Sequence
    ]
  where
    rsaPubKeyDER = encodeASN1' DER
        [ Start Sequence
        , IntVal (RSA.public_n pub)
        , IntVal (RSA.public_e pub)
        , End Sequence
        ]

-- | An extensionRequest attribute carrying a SubjectAltName extension.
extensionRequestAttr :: [String] -> [ASN1]
extensionRequestAttr domains =
    [ Start Sequence                   -- Attribute
    , OID [1,2,840,113549,1,9,14]     -- extensionRequest OID
    , Start Set
    , Start Sequence                   -- Extensions
    , Start Sequence                   -- Extension: subjectAltName
    , OID [2,5,29,17]                 -- subjectAltName OID
    , OctetString sanValue
    , End Sequence
    , End Sequence
    , End Set
    , End Sequence
    ]
  where
    -- DER-encoded GeneralNames SEQUENCE; each domain is [2] IMPLICIT IA5String
    sanValue = encodeASN1' DER $
        [ Start Sequence ]
        ++ map (\d -> Other Context 2 (BS8.pack d)) domains
        ++ [ End Sequence ]

-- ---------------------------------------------------------------------------
-- RSA key persistence (PKCS#1 PEM)
-- ---------------------------------------------------------------------------

loadOrCreateAccountKey :: FilePath -> IO RSA.PrivateKey
loadOrCreateAccountKey path = do
    exists <- doesFileExist path
    if exists
        then do
            bs <- BS.readFile path
            case parseRSAPrivKey bs of
                Right k  -> return k
                Left err -> do
                    hPutStrLn stderr $
                        "[ACME] Cannot parse account key (" ++ err ++ "); regenerating"
                    genAndSave
        else genAndSave
  where
    genAndSave = do
        (_, priv) <- RSA.generate 256 65537  -- 2048-bit
        BS.writeFile path (rsaPrivKeyToPEM priv)
        return priv

rsaPrivKeyToPEM :: RSA.PrivateKey -> ByteString
rsaPrivKeyToPEM key = pemWriteBS $ PEM "RSA PRIVATE KEY" [] (encodeASN1' DER asn1)
  where
    pub  = RSA.private_pub key
    asn1 = [ Start Sequence
           , IntVal 0
           , IntVal (RSA.public_n  pub)
           , IntVal (RSA.public_e  pub)
           , IntVal (RSA.private_d key)
           , IntVal (RSA.private_p key)
           , IntVal (RSA.private_q key)
           , IntVal (RSA.private_dP   key)
           , IntVal (RSA.private_dQ   key)
           , IntVal (RSA.private_qinv key)
           , End Sequence
           ]

parseRSAPrivKey :: ByteString -> Either String RSA.PrivateKey
parseRSAPrivKey bs = do
    pems <- pemParseBS bs
    pem  <- maybe (Left "Empty PEM") Right (listToMaybe pems)
    asn1 <- either (Left . show) Right (decodeASN1' DER (pemContent pem))
    case asn1 of
        [ Start Sequence, IntVal 0
          , IntVal n, IntVal e, IntVal d
          , IntVal p, IntVal q
          , IntVal dp, IntVal dq, IntVal qinv
          , End Sequence ] ->
            Right RSA.PrivateKey
                { RSA.private_pub  = RSA.PublicKey
                    { RSA.public_size = BS.length (integerToBS n)
                    , RSA.public_n    = n
                    , RSA.public_e    = e
                    }
                , RSA.private_d    = d
                , RSA.private_p    = p
                , RSA.private_q    = q
                , RSA.private_dP   = dp
                , RSA.private_dQ   = dq
                , RSA.private_qinv = qinv
                }
        _ -> Left "Unexpected ASN.1 structure"

-- ---------------------------------------------------------------------------
-- Cryptographic primitives
-- ---------------------------------------------------------------------------

signRS256 :: RSA.PrivateKey -> ByteString -> IO ByteString
signRS256 key msg = do
    result <- PKCS15.signSafer (Just SHA256) key msg
    case result of
        Left  err -> throwAcme $ "RSA signing failed: " ++ show err
        Right sig -> return sig

sha256bs :: ByteString -> ByteString
sha256bs = convert . hashWith SHA256

-- | Base64url without padding (RFC 4648 §5).
b64url :: ByteString -> ByteString
b64url = BS8.filter (/= '=') . B64URL.encode

-- | Minimal big-endian unsigned encoding of a non-negative 'Integer'.
integerToBS :: Integer -> ByteString
integerToBS 0 = BS.singleton 0
integerToBS n = BS.pack (reverse (go n))
  where
    go 0 = []
    go x = fromIntegral (x `mod` 256) : go (x `div` 256)

-- ---------------------------------------------------------------------------
-- Aeson helpers
-- ---------------------------------------------------------------------------

decodeBody :: String -> LBS.ByteString -> IO Aeson.Value
decodeBody label body =
    case Aeson.eitherDecode body of
        Left err -> throwAcme $
            "Failed to parse " ++ label ++ " response: " ++ err
            ++ " (body: " ++ take 500 (BS8.unpack (LBS.toStrict body)) ++ ")"
        Right v  -> return v

lookupText :: Text -> Aeson.Value -> Maybe Text
lookupText key (Aeson.Object o) =
    case fmap Aeson.fromJSON (AKM.lookup (AKey.fromText key) o) of
        Just (Aeson.Success t) -> Just t
        _                      -> Nothing
lookupText _ _ = Nothing

lookupArray :: Text -> Aeson.Value -> Maybe [Aeson.Value]
lookupArray key (Aeson.Object o) =
    case fmap Aeson.fromJSON (AKM.lookup (AKey.fromText key) o) of
        Just (Aeson.Success xs) -> Just xs
        _                       -> Nothing
lookupArray _ _ = Nothing

-- ---------------------------------------------------------------------------
-- Misc helpers
-- ---------------------------------------------------------------------------

sanitizeDomain :: Text -> FilePath
sanitizeDomain = map (\c -> if c == '/' then '_' else c) . T.unpack

logInfo :: String -> IO ()
logInfo msg = hPutStrLn stderr $ "[ACME] " ++ msg
