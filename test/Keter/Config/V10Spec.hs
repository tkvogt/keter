{-# LANGUAGE OverloadedStrings #-}

module Keter.Config.V10Spec (tests) where

import Data.ByteString.Char8 qualified as BS
import Data.Set qualified as Set
import Keter.Common (SSLConfig (..))
import Keter.Config.V10
import Keter.Yaml.FilePath (decodeFileRelative)
import System.FilePath (takeFileName)
import System.IO (hClose)
import System.IO.Temp (withSystemTempFile)
import Test.Tasty
import Test.Tasty.HUnit

tests :: TestTree
tests = testGroup "Keter.Config.V10 (WebAppConfig parsing)"
  [ testCase "port-env-vars parses a list of variable names" casePortEnvVarsList
  , testCase "port-env-vars defaults to empty when omitted" casePortEnvVarsDefault
  , testCase "port-env-vars parses empty list" casePortEnvVarsEmpty
  , testCase "ssl: acme parses" caseSslAcme
  , testCase "acme config parses" caseAcmeConfig
  , testCase "acme config defaults directory and cert-dir" caseAcmeDefaults
  ]

-- | Helper: write YAML bytes to a temp file, then parse as a 'WebAppConfig'.
parseWebAppConfig :: BS.ByteString -> IO (WebAppConfig ())
parseWebAppConfig yaml =
    withSystemTempFile "keter-test-.yaml" $ \fp h -> do
        BS.hPut h yaml
        hClose h
        result <- decodeFileRelative fp
        case result of
            Left err  -> assertFailure ("Failed to parse: " <> show err) >> error "unreachable"
            Right wac -> return wac

casePortEnvVarsList :: IO ()
casePortEnvVarsList = do
    wac <- parseWebAppConfig $ BS.unlines
        [ "exec: /tmp/myapp"
        , "host: example.com"
        , "port-env-vars:"
        , "  - YESOD_PORT"
        , "  - RAILS_PORT"
        ]
    waconfigPortEnvVars wac @?= Set.fromList ["YESOD_PORT", "RAILS_PORT"]

casePortEnvVarsDefault :: IO ()
casePortEnvVarsDefault = do
    wac <- parseWebAppConfig $ BS.unlines
        [ "exec: /tmp/myapp"
        , "host: example.com"
        ]
    waconfigPortEnvVars wac @?= Set.empty

casePortEnvVarsEmpty :: IO ()
casePortEnvVarsEmpty = do
    wac <- parseWebAppConfig $ BS.unlines
        [ "exec: /tmp/myapp"
        , "host: example.com"
        , "port-env-vars: []"
        ]
    waconfigPortEnvVars wac @?= Set.empty

caseSslAcme :: IO ()
caseSslAcme = do
    wac <- parseWebAppConfig $ BS.unlines
        [ "exec: /tmp/myapp"
        , "host: example.com"
        , "ssl: acme"
        ]
    waconfigSsl wac @?= SSLAcme

parseAcmeConfig :: BS.ByteString -> IO AcmeConfig
parseAcmeConfig yaml =
    withSystemTempFile "keter-acme-test-.yaml" $ \fp h -> do
        BS.hPut h yaml
        hClose h
        result <- decodeFileRelative fp
        case result of
            Left err -> assertFailure ("Failed to parse ACME config: " <> show err) >> error "unreachable"
            Right cfg -> return cfg

caseAcmeConfig :: IO ()
caseAcmeConfig = do
    cfg <- parseAcmeConfig $ BS.unlines
        [ "email: test@example.com"
        , "directory: https://acme.example/directory"
        , "cert-dir: acme"
        ]
    acmeEmail cfg @?= "test@example.com"
    acmeDirectory cfg @?= "https://acme.example/directory"
    takeFileName (acmeCertDir cfg) @?= "acme"

caseAcmeDefaults :: IO ()
caseAcmeDefaults = do
    cfg <- parseAcmeConfig $ BS.unlines
        [ "email: test@example.com"
        ]
    acmeDirectory cfg @?= defaultAcmeDirectoryUrl
    takeFileName (acmeCertDir cfg) @?= "acme"
