{-# LANGUAGE RecursiveDo #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE QuasiQuotes #-}
{-# LANGUAGE TypeFamilies #-}

module Main where

import           Data.Bool
import           Data.ByteString.UTF8   (ByteString)
import qualified Data.ByteString.Lazy.Char8 as BL8
import           Network.HTTP.Types.URI (urlEncode)
import           Data.Digest.Pure.SHA
import           Crypto.Hash.SHA1       (hash)
import           Crypto.MAC.HMAC        (hmac)
import           Data.String.QQ
import           Data.Time
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BSC
import qualified Data.ByteString.Base64 as B64
import           Text.Printf
import           Reflex
import           Reflex.Dom
import           Reflex.Dynamic.TH
import           Reflex.Dom.Contrib.Widgets.Common

data PostPolicy t = PostPolicy
  { ppBucket       :: Dynamic t String
  , ppKey          :: Dynamic t String
  , ppExpires      :: Dynamic t String -- UTCTime
  , ppAcl          :: Dynamic t String
  , ppSuccess      :: Dynamic t String
  , ppContent      :: Dynamic t String
  , ppAmzMetaUuid  :: Dynamic t String
  , ppAmzCred      :: Dynamic t String
  , ppAmzAlgo      :: Dynamic t String
  --, ppAmzDate      :: String
  , ppAmzMetaTag   :: Dynamic t String
  , ppAmzDate      :: Dynamic t String
  }


postPolicyWidget :: MonadWidget t m => m (PostPolicy t)
postPolicyWidget = do
  el "table" $ PostPolicy
    <$> row "Bucket" "examplebucket"
    <*> row "Key starts" "/user/user1/"
    -- ppExp <- fmap _hWidget_value $ el "tr" $ do
    --            el "td" "Expiration"
    --            dateWidget def { _widgetConfig_initialValue = fromGregorian 2017 1 1}
    <*> row "Expire time" "2013-08-06T12:00:00.000Z"
    <*> row "Acl" "public-read"
    <*> row "Success redirect" "http://acl6.s3.amazonaws.com/successful_upload.html"
    <*> row "Content-Type" "image/" -- TODO
    <*> row "Amazon Meta UUID" "14365123651274" -- TODO
    <*> row "Amazon Meta Credential" "AKIAIOSFODNN7EXAMPLE/20130806/us-east-1/s3/aws4_request"
    <*> row "Hash Algorithm" "AWS4-HMAC-SHA256" -- TODO
    <*> row "Meta Tag" "" -- TODO
    <*> row "Amz Date" "20130806T000000Z"



-- | HMAC-SHA1 Encrypted Signature
sign :: BSC.ByteString -> BSC.ByteString -> BSC.ByteString
sign secretKey url = urlEncode True . B64.encode . BSC.pack . showDigest $ hmacSha1 (BL8.fromStrict secretKey) (BL8.fromStrict url)


row :: MonadWidget t m => String -> String -> m (Dynamic t String)
row l d = do
  el "tr" $ do
    el "td" (text l)
    _textInput_value <$> textInput def { _textInputConfig_initialValue = d}

docFmt :: String
docFmt = [s|
{ "expiration": "%s",
  "conditions": [
    {"bucket": "%s"},
    ["starts-with", "$key", "%s"],
    {"acl": "%s"},
    {"success_action_redirect": "%s"},
    ["starts-with", "$Content-Type", "%s"],
    {"x-amz-meta-uuid": "%s"},
    ["starts-with", "$x-amz-meta-tag", "%s"],

    {"x-amz-credential": "%s"},
    {"x-amz-algorithm": "%s"},
    {"x-amz-date": "%s" }
  ]
}
|]


formFmt :: String
formFmt = [s|
<form action="http://%s.s3.amazonaws.com/" method="post" enctype="multipart/form-data">
  <input type="input"  name="key" value="%s${filename}" /><br />
  <input type="hidden" name="acl" value="%s" />
  <input type="hidden" name="success_action_redirect" value="%s" />
  <input type="input"  name="Content-Type" value="%s" /><br />
  <input type="hidden" name="x-amz-meta-uuid" value="%s" />
  <input type="text"   name="X-Amz-Credential" value="%s" />
  <input type="text"   name="X-Amz-Algorithm" value="%s" />
  <input type="text"   name="X-Amz-Date" value="%s" />

  <input type="input"  name="x-amz-meta-tag" value="%s" /><br />
  <input type="hidden" name="Policy" value='%s' />
  <input type="hidden" name="X-Amz-Signature" value="%s" />
  <br/>
  <input type="file"   name="file" /> <br />
  <input type="submit" name="submit" value="Upload" />
</form>
|]


toForm :: MonadWidget t m => PostPolicy t
                          -> Dynamic t BSC.ByteString
                          -> Dynamic t BSC.ByteString
                          -> m (Dynamic t String)
toForm PostPolicy{..} encodedPolicy signedPolicy =
  $(qDyn [| printf formFmt $(unqDyn [|ppBucket|])
                          $(unqDyn [|ppKey|])
                          $(unqDyn [|ppAcl|])
                          $(unqDyn [|ppSuccess|])
                          $(unqDyn [|ppContent|])
                          $(unqDyn [|ppAmzMetaUuid|])
                          $(unqDyn [|ppAmzCred|])
                          $(unqDyn [|ppAmzAlgo|])
                          $(unqDyn [|ppAmzDate|])
                          $(unqDyn [|ppAmzMetaTag|])
                          (BSC.unpack $(unqDyn [|encodedPolicy|]))
                          (BSC.unpack $(unqDyn [|signedPolicy|])) |])

toDoc :: MonadWidget t m => PostPolicy t -> m (Dynamic t String)
toDoc PostPolicy{..} =
  $(qDyn [| printf docFmt $(unqDyn [|ppExpires|])
                          $(unqDyn [|ppBucket|])
                          $(unqDyn [|ppKey|])
                          $(unqDyn [|ppAcl|])
                          $(unqDyn [|ppSuccess|])
                          $(unqDyn [|ppContent|])
                          $(unqDyn [|ppAmzMetaUuid|])
                          $(unqDyn [|ppAmzMetaTag|])
                          $(unqDyn [|ppAmzCred|])
                          $(unqDyn [|ppAmzAlgo|])
                          $(unqDyn [|ppAmzDate|]) |])

main :: IO ()
main = mainWidget $ mdo
  text "S3 secret key"
  key        <- _textInput_value <$> textInput def
  el "br" (return ())
  postpolicy <- postPolicyWidget
  policyDoc  <- toDoc postpolicy
  encodedPolicy <- mapDyn (B64.encode . BSC.pack) policyDoc
  signedPolicy <- combineDyn (\k p -> sign (BSC.pack k) (BSC.pack p)) key policyDoc
  policyForm <- toForm postpolicy encodedPolicy signedPolicy
  el "br" (return ())
  elClass "div" "doc" $ el "pre" $ dynText policyDoc
  el "br" (return ())
  elClass "div" "formdiv" $ el "pre" $ dynText policyForm
