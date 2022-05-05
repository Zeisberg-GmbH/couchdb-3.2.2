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

-module(couch_encryption_manager).

-export([key_id/1, key/1, encryption_options/1]).

-spec key_id(DbName :: binary()) -> KeyID :: binary() | false.
key_id(_DbName) ->
    <<"default">>.

-spec key(KeyID :: binary()) -> KEK :: binary() | not_found.
key(<<"default">>) ->
    <<0:256>>;
key(_) ->
    not_found.

%% Extract just the encryption related options from an options list.
encryption_options(Options) ->
    case lists:keyfind(key_id, 1, Options) of
        false -> [];
        {key_id, KeyID} -> [{key_id, KeyID}]
    end.
