{-# LANGUAGE OverloadedStrings #-}

module Keter.Proxy.ACMEChallengeSpec (tests) where

import Control.Concurrent (forkIO, threadDelay)
import Control.Exception (try)
import Control.Lens ((&), (.~), (^.))
import Control.Monad (void)
import Control.Monad.Logger (runLoggingT)
import Control.Monad.Reader (runReaderT)
import Data.ByteString (ByteString)
import Data.ByteString.Lazy qualified as LBS
import Data.IORef (IORef, newIORef)
import Data.Map.Strict qualified as Map
import Keter.Config.V10
import Keter.Context (runKeterM)
import Keter.Proxy
import Network.HTTP.Conduit (Manager)
import Network.HTTP.Conduit qualified as HTTP
import Network.HTTP.Types.Status (statusCode)
import Network.Wreq qualified as Wreq
import Test.Tasty
import Test.Tasty.HUnit

tests :: TestTree
tests = testGroup "Keter.Proxy ACME HTTP-01"
  [ testCase "challenge token extraction" caseTokenExtraction
  , testCase "known token returns key authorization" caseKnownToken
  , testCase "unknown token returns 404" caseUnknownToken
  ]

caseTokenExtraction :: IO ()
caseTokenExtraction = do
  acmeChallengeToken "/.well-known/acme-challenge/abc" @?= Just "abc"
  acmeChallengeToken "/.well-known/acme-challenge/" @?= Nothing
  acmeChallengeToken "/some/other/path" @?= Nothing

mkAcmeSettings :: Manager -> IORef (Map.Map ByteString ByteString) -> ProxySettings
mkAcmeSettings manager challenges = MkProxySettings
  { psHostLookup          = \_ -> pure Nothing
  , psManager             = manager
  , psTrustForwardedFor   = \_ -> True
  , psUnknownHost         = const ""
  , psMissingHost         = ""
  , psProxyException      = "proxy error"
  , psIpFromHeader        = False
  , psConnectionTimeBound = 5 * 60 * 1000
  , psHealthcheckPath     = Nothing
  , psAcmeChallenges      = challenges
  }

runProxyOn :: ProxySettings -> Int -> IO ()
runProxyOn settings listenPort = void . forkIO $
  flip runReaderT settings $
  flip runLoggingT (\_ _ _ _ -> pure ()) $
  runKeterM $
    reverseProxy (LPInsecure "*" listenPort)

caseKnownToken :: IO ()
caseKnownToken = do
  ref <- newIORef (Map.fromList [("tok" :: ByteString, "keyauth" :: ByteString)])
  manager <- HTTP.newManager HTTP.tlsManagerSettings
  runProxyOn (mkAcmeSettings manager ref) 6797
  threadDelay 250000
  r <- Wreq.getWith
    (Wreq.defaults & Wreq.header "Host" .~ ["acme.test"])
    "http://127.0.0.1:6797/.well-known/acme-challenge/tok"
  r ^. Wreq.responseStatus . Wreq.statusCode @?= 200
  r ^. Wreq.responseBody @?= LBS.fromStrict ("keyauth" :: ByteString)

caseUnknownToken :: IO ()
caseUnknownToken = do
  ref <- newIORef Map.empty
  manager <- HTTP.newManager HTTP.tlsManagerSettings
  runProxyOn (mkAcmeSettings manager ref) 6798
  threadDelay 250000
  result <- try $ Wreq.getWith
    (Wreq.defaults & Wreq.header "Host" .~ ["acme.test"])
    "http://127.0.0.1:6798/.well-known/acme-challenge/missing"
  case result of
    Left (HTTP.HttpExceptionRequest _ (HTTP.StatusCodeException resp _)) ->
      statusCode (HTTP.responseStatus resp) @?= 404
    Left e -> assertFailure ("Unexpected exception: " <> show e)
    Right r -> r ^. Wreq.responseStatus . Wreq.statusCode @?= 404
