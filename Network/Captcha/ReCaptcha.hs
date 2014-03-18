{-
Copyright (c) 2008 John MacFarlane
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:

Redistributions of source code must retain the above copyright
notice, this list of conditions and the following disclaimer.

Redistributions in binary form must reproduce the above copyright
notice, this list of conditions and the following disclaimer in the
documentation and/or other materials provided with the distribution.

Neither the name of John MacFarlane nor the names of this software's
contributors may be used to endorse or promote products derived from
this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT OWNER OR
CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
-}

module Network.Captcha.ReCaptcha
       ( captchaFields
       , validateCaptcha
       )
where
import Text.XHtml
import Network.Browser
import Network.HTTP
import Network.URI

-- | Returns HTML element to be inserted in the form for which a CAPTCHA is wanted.
captchaFields :: String       -- ^ reCAPTCHA public key
              -> Maybe String -- ^ @Nothing@ or @Just@ an error message returned by previous validate attempt
              -> Html
captchaFields recaptchaPublicKey mbErrorMsg =
  (script ! [src (captchaURL "challenge"), thetype "text/javascript"] << noHtml) +++
  noscript << [ iframe ! [src (captchaURL "noscript"), height "300", width "500", frameborder 0] << noHtml
              , br
              , textarea ! [name "recaptcha_challenge_field", rows "3", cols "40"] << noHtml
              , input ! [thetype "hidden", name "recaptcha_response_field", value "manual_challenge"]
              ]
  where captchaURL s = "https://www.google.com/recaptcha/api/" ++ s ++ "?k=" ++ recaptchaPublicKey ++
          case mbErrorMsg of
               Just e  -> "?error=" ++ e
               Nothing -> ""

-- | Verify a CAPTCHA.
validateCaptcha :: String                 -- ^ reCAPTCHA private key
                -> String                 -- ^ IP address of the user who solved the CAPTCHA
                -> String                 -- ^ value of the recaptcha_challenge_field 
                -> String                 -- ^ value of the recaptcha_response_field
                -> IO (Either String ())  -- ^ @Left@ error message, or @Right ()@ for success
validateCaptcha recaptchaPrivateKey ipaddress challenge response = do
  let verifyURIString = "https://www.google.com/recaptcha/api/verify"
  let verifyURI = case parseURI verifyURIString of
                       Just uri  -> uri
                       Nothing   -> error $ "Could not parse URI: " ++ verifyURIString
  let contents = urlEncodeVars  [("privatekey", recaptchaPrivateKey),
                                 ("remoteip", ipaddress),
                                 ("challenge", challenge),
                                 ("response", response)]
  let req = Request { rqURI = verifyURI,
                      rqMethod = POST,
                      rqHeaders = [ Header HdrContentType "application/x-www-form-urlencoded",
                                    Header HdrContentLength (show $ length contents) ],
                      rqBody = contents }
  (_, resp) <- browse (request req)
  if rspCode resp == (2,0,0)
     then do
       let respLines = lines $ rspBody resp
       if null respLines
          then return $ Left "response-body-empty"
          else if head respLines == "true"
                  then return $ Right ()
                  else if length respLines >= 2
                          then return $ Left $ respLines !! 1
                          else return $ Left "no-error-message"
     else return $ Left "response-code-not-200"


