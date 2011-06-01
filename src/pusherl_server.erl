-module(pusherl_server).
-behaviour(gen_server).
-define(SERVER, ?MODULE).
-define(JP, fun(K,V) -> string:join([K,V],"=") end).

-record(state,{app_id, key, secret}).

%% ------------------------------------------------------------------
%% API Function Exports
%% ------------------------------------------------------------------

-export([start_link/0]).

%% ------------------------------------------------------------------
%% gen_server Function Exports
%% ------------------------------------------------------------------

-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2, code_change/3]).

%% ------------------------------------------------------------------
%% API Function Definitions
%% ------------------------------------------------------------------

start_link() ->
  gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

%% ------------------------------------------------------------------
%% gen_server Function Definitions
%% ------------------------------------------------------------------

init(_) ->
  {ok, PusherAppId} = application:get_env(pusher_app_id),
  {ok, PusherKey} = application:get_env(pusher_key),
  {ok, PusherSecret} = application:get_env(pusher_secret),
  {ok, #state{app_id=PusherAppId, key=PusherKey, secret=PusherSecret}}.

handle_call({push, {ChannelName, EventName, Payload}}, _From, State) ->
  case http_request(ChannelName, EventName, Payload, State) of
    {ok, _} -> {reply, ok, State};
    {error, _} -> {reply, error, State}
  end;
handle_call(_Request, _From, State) ->
  {noreply, ok, State}.

handle_cast({push, {ChannelName, EventName, Payload}}, State) ->
  case http_request(ChannelName, EventName, Payload, State) of
    {ok, _} -> {noreply, ok, State};
    {error, _} -> {noreply, error, State}
  end;
handle_cast(_Msg, State) ->
  {noreply, State}.

handle_info(_Info, State) ->
  {noreply, State}.

terminate(_Reason, _State) ->
  ok.

code_change(_OldVsn, State, _Extra) ->
  {ok, State}.

%% ------------------------------------------------------------------
%% Internal Function Definitions
%% ------------------------------------------------------------------
http_request(ChannelName, EventName, Payload, Config) when is_list(ChannelName), is_record(Config, state) ->
  {ok, ReqProps} = http_request_props(Payload, EventName, ChannelName, Config),
	httpc:request(post, ReqProps, [], []).

http_request_props(Payload, EventName, ChannelName, #state{app_id=AppId, key=AppKey, secret=AppSecret}) ->
	Md5String = lists:flatten([io_lib:format("~2.16.0b",[N]) || <<N>> <= crypto:md5(Payload)]),
  ToSign = ["POST",
				lists:flatten(["/apps/", AppId, "/channels/", ChannelName, "/events"]),
				string:join([?JP("auth_key", AppKey),
        ?JP("auth_timestamp", get_time_as_string()),
        ?JP("auth_version", "1.0"),
        ?JP("body_md5", Md5String),
				?JP("name", EventName)
				],"&")
  ],
	AuthSignature = signed_params(ToSign, AppSecret),
	QueryParams = [
		?JP("auth_key", AppKey),
	  ?JP("auth_timestamp", get_time_as_string()),
	  ?JP("auth_version","1.0"),
	  ?JP("body_md5", Md5String),
		?JP("auth_signature", AuthSignature),
		?JP("name", EventName)
	],
  Url = http_api_url(AppId, ChannelName, QueryParams),
  {ok, {Url, [], "application/x-www-form-urlencoded", Payload}}.

http_api_url(AppId, ChannelName, QueryParams) ->
  QueryString = string:join(QueryParams,"&"),
  lists:flatten(["http://api.pusherapp.com/apps/",AppId,"/channels/",ChannelName,"/events?", QueryString]).

get_time_as_string() ->
  {M, S, _} = now(),
  integer_to_list(((M * 1000000) + S)).

signed_params(Params, Secret) ->
	lists:flatten([io_lib:format("~2.16.0b",[N]) || <<N:8>> <= sha2:hmac_sha256(Secret, string:join(Params,"\n"))]).
  