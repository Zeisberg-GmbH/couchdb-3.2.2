% Licensed under the Apache License, Version 2.0 (the "License"); you may not
% use this file except in compliance with the License. You may obtain a copy of
% the License at
%
%   http://www.apache.org/licenses/LICENSE-2.0
%
% Unless required by applicable law or agreed to in writing, software
% distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
% WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
% License for the specific language governing permissions and limitations under
% the License.

-module(couch_encryption_manager_demo).
-behaviour(couch_encryption_manager).

-export([new_dek/1, unwrap_dek/2]).

new_dek(_DbName) ->
    KeyID = <<"default">>,
    KEK = <<0:256>>,
    DEK = crypto:strong_rand_bytes(32),
    {ok, KeyID, DEK, wrap_key(KeyID, KEK, DEK)}.

unwrap_dek(<<"default">> = KeyID, WEK) ->
    KEK = <<0:256>>,
    unwrap_key(KeyID, KEK, WEK);
unwrap_dek(_, _) ->
    {error, invalid_key_id}.

wrap_key(KeyID, KEK, DEK) when is_binary(KEK), is_binary(DEK) ->
    IV = crypto:strong_rand_bytes(16),
    {<<_:32/binary>> = CipherText, <<_:16/binary>> = CipherTag} =
        crypto:crypto_one_time_aead(aes_256_gcm, KEK, IV, DEK, KeyID, 16, true),
    <<IV:16/binary, CipherText/binary, CipherTag/binary>>.

unwrap_key(KeyID, KEK, <<IV:16/binary, CipherText:32/binary, CipherTag:16/binary>>) when
    is_binary(KEK)
->
    case crypto:crypto_one_time_aead(aes_256_gcm, KEK, IV, CipherText, KeyID, CipherTag, false) of
        error ->
            {error, unwrap_failed};
        DEK ->
            {ok, DEK}
    end;
unwrap_key(_KeyID, _KEK, _) ->
    {error, malformed_wrapped_key}.