defprotocol Boruta.Oauth.Authorization do
  @moduledoc """
  """

  @doc """
  Checks if request is valid for token creation for given request, depending of implementation.
  """
  @spec preauthorize(request :: any()) ::
          {:ok, Boruta.Oauth.AuthorizationSuccess.t()} | {:error, Boruta.Oauth.Error.t()}
  def preauthorize(request)

  @doc """
  Creates and returns a token for given request, depending of implementation.
  """
  @spec token(request :: any()) ::
          {:ok,
           Boruta.Oauth.Token.t()
           | %{
               (type :: :code | :token | :id_token) =>
                 token :: Boruta.Oauth.Token.t() | String.t()
             }}
          | {:error, reason :: term()}
          | {:error, Boruta.Oauth.Error.t()}
  def token(request)
end

defmodule Boruta.Oauth.AuthorizationSuccess do
  @moduledoc """
  Struct encapsulating an authorization success
  """

  defstruct response_types: [],
            client: nil,
            redirect_uri: nil,
            sub: nil,
            scope: nil,
            state: nil,
            nonce: nil,
            code: nil,
            code_challenge: nil,
            code_challenge_method: nil

  @type t :: %__MODULE__{
          response_types: list(String.t()),
          client: Boruta.Oauth.Client.t(),
          code: Boruta.Oauth.Token.t(),
          redirect_uri: String.t(),
          sub: String.t(),
          scope: String.t(),
          state: String.t(),
          nonce: String.t(),
          code_challenge: String.t(),
          code_challenge_method: String.t()
        }
end

defimpl Boruta.Oauth.Authorization, for: Boruta.Oauth.ClientCredentialsRequest do
  alias Boruta.AccessTokensAdapter
  alias Boruta.Oauth.Authorization
  alias Boruta.Oauth.AuthorizationSuccess
  alias Boruta.Oauth.ClientCredentialsRequest
  alias Boruta.Oauth.Token

  def preauthorize(%ClientCredentialsRequest{
        client_id: client_id,
        client_secret: client_secret,
        scope: scope,
        grant_type: grant_type
      }) do
    with {:ok, client} <-
           Authorization.Client.authorize(
             id: client_id,
             secret: client_secret,
             grant_type: grant_type
           ),
         {:ok, scope} <- Authorization.Scope.authorize(scope: scope, against: %{client: client}) do
      {:ok, %AuthorizationSuccess{client: client, scope: scope}}
    end
  end

  def token(request) do
    with {:ok, %AuthorizationSuccess{client: client, scope: scope}} <- preauthorize(request) do
      # TODO rescue from creation errors
      with {:ok, access_token} <-
             AccessTokensAdapter.create(
               %{
                 client: client,
                 scope: scope
               },
               refresh_token: true
             ) do
        {:ok, %{token: access_token}}
      end
    end
  end
end

defimpl Boruta.Oauth.Authorization, for: Boruta.Oauth.PasswordRequest do
  alias Boruta.AccessTokensAdapter
  alias Boruta.Oauth.Authorization
  alias Boruta.Oauth.AuthorizationSuccess
  alias Boruta.Oauth.PasswordRequest
  alias Boruta.Oauth.ResourceOwner
  alias Boruta.Oauth.Token

  def preauthorize(%PasswordRequest{
        client_id: client_id,
        client_secret: client_secret,
        username: username,
        password: password,
        scope: scope,
        grant_type: grant_type
      }) do
    with {:ok, client} <-
           Authorization.Client.authorize(
             id: client_id,
             secret: client_secret,
             grant_type: grant_type
           ),
         {:ok, %ResourceOwner{sub: sub} = resource_owner} <-
           Authorization.ResourceOwner.authorize(username: username, password: password),
         {:ok, scope} <-
           Authorization.Scope.authorize(
             scope: scope,
             against: %{client: client, resource_owner: resource_owner}
           ) do
      {:ok, %AuthorizationSuccess{client: client, sub: sub, scope: scope}}
    end
  end

  @dialyzer {:no_match, token: 1}
  def token(request) do
    with {:ok, %AuthorizationSuccess{client: client, sub: sub, scope: scope}} <-
           preauthorize(request) do
      # TODO rescue from creation errors
      with {:ok, access_token} <-
             AccessTokensAdapter.create(
               %{
                 client: client,
                 sub: sub,
                 scope: scope
               },
               refresh_token: true
             ) do
        {:ok, %{token: access_token}}
      end
    end
  end
end

defimpl Boruta.Oauth.Authorization, for: Boruta.Oauth.AuthorizationCodeRequest do
  import Boruta.Config, only: [token_generator: 0]

  alias Boruta.AccessTokensAdapter
  alias Boruta.CodesAdapter
  alias Boruta.Oauth.Authorization
  alias Boruta.Oauth.AuthorizationSuccess
  alias Boruta.Oauth.AuthorizationCodeRequest
  alias Boruta.Oauth.ResourceOwner
  alias Boruta.Oauth.Scope
  alias Boruta.Oauth.Token

  def preauthorize(%AuthorizationCodeRequest{
        client_id: client_id,
        code: code,
        redirect_uri: redirect_uri,
        grant_type: grant_type,
        code_verifier: code_verifier
      }) do
    with {:ok, client} <-
           Authorization.Client.authorize(
             id: client_id,
             redirect_uri: redirect_uri,
             grant_type: grant_type,
             code_verifier: code_verifier
           ),
         {:ok, code} <-
           Authorization.Code.authorize(%{
             value: code,
             redirect_uri: redirect_uri,
             client: client,
             code_verifier: code_verifier
           }),
         {:ok, %ResourceOwner{sub: sub}} <-
           Authorization.ResourceOwner.authorize(resource_owner: code.resource_owner) do
      {:ok,
       %AuthorizationSuccess{
         client: client,
         code: code,
         redirect_uri: redirect_uri,
         sub: sub,
         scope: code.scope,
         nonce: code.nonce
       }}
    end
  end

  def token(request) do
    with {:ok,
          %AuthorizationSuccess{
            client: client,
            code: code,
            redirect_uri: redirect_uri,
            sub: sub,
            scope: scope,
            nonce: nonce
          }} <-
           preauthorize(request),
         # TODO rescue from creation errors
         {:ok, access_token} <-
           AccessTokensAdapter.create(
             %{
               client: client,
               redirect_uri: redirect_uri,
               sub: sub,
               scope: scope
             },
             refresh_token: true
           ),
         {:ok, _code} <- CodesAdapter.revoke(code) do
      case String.match?(scope, ~r/#{Scope.openid().name}/) do
        true ->
          id_token = %Token{
            type: "id_token",
            redirect_uri: redirect_uri,
            client: client,
            sub: sub,
            scope: scope,
            inserted_at: DateTime.utc_now(),
            nonce: nonce
          }

          id_token = %{id_token | value: token_generator().generate(:id_token, id_token)}

          {:ok, %{token: access_token, id_token: id_token}}

        false ->
          {:ok, %{token: access_token}}
      end
    end
  end
end

defimpl Boruta.Oauth.Authorization, for: Boruta.Oauth.TokenRequest do
  import Boruta.Config, only: [token_generator: 0]

  alias Boruta.AccessTokensAdapter
  alias Boruta.Oauth.Authorization
  alias Boruta.Oauth.AuthorizationSuccess
  alias Boruta.Oauth.ResourceOwner
  alias Boruta.Oauth.Scope
  alias Boruta.Oauth.TokenRequest
  alias Boruta.Oauth.Token

  def preauthorize(%TokenRequest{
        response_types: response_types,
        client_id: client_id,
        redirect_uri: redirect_uri,
        resource_owner: resource_owner,
        state: state,
        nonce: nonce,
        scope: scope,
        grant_type: grant_type
      }) do
    with {:ok, client} <-
           Authorization.Client.authorize(
             id: client_id,
             redirect_uri: redirect_uri,
             grant_type: grant_type
           ),
         {:ok, %ResourceOwner{sub: sub}} <-
           Authorization.ResourceOwner.authorize(resource_owner: resource_owner),
         {:ok, scope} <-
           Authorization.Scope.authorize(
             scope: scope,
             against: %{client: client, resource_owner: resource_owner}
           ) do
      {:ok,
       %AuthorizationSuccess{
         response_types: response_types,
         client: client,
         redirect_uri: redirect_uri,
         sub: sub,
         scope: scope,
         state: state,
         nonce: nonce
       }}
    end
  end

  def token(request) do
    with {:ok,
          %AuthorizationSuccess{
            response_types: response_types,
            client: client,
            redirect_uri: redirect_uri,
            sub: sub,
            scope: scope,
            state: state,
            nonce: nonce
          }} <- preauthorize(request) do
      # TODO rescue from creation errors
      Enum.reduce(response_types, {:ok, %{}}, fn
        "id_token", {:ok, tokens} ->
          case String.match?(scope, ~r/#{Scope.openid().name}/) do
            true ->
              id_token = %Token{
                type: "id_token",
                redirect_uri: redirect_uri,
                client: client,
                sub: sub,
                scope: scope,
                state: state,
                nonce: nonce,
                inserted_at: DateTime.utc_now()
              }

              id_token = %{id_token | value: token_generator().generate(:id_token, id_token)}

              {:ok, Map.put(tokens, :id_token, id_token)}

            false ->
              {:ok, tokens}
          end

        "token", {:ok, tokens} ->
          with {:ok, access_token} <-
                 AccessTokensAdapter.create(
                   %{
                     client: client,
                     redirect_uri: redirect_uri,
                     sub: sub,
                     scope: scope,
                     state: state
                   },
                   refresh_token: false
                 ) do
            {:ok, Map.put(tokens, :token, access_token)}
          end
      end)
    end
  end
end

defimpl Boruta.Oauth.Authorization, for: Boruta.Oauth.CodeRequest do
  alias Boruta.CodesAdapter
  alias Boruta.Oauth.Authorization
  alias Boruta.Oauth.AuthorizationSuccess
  alias Boruta.Oauth.Client
  alias Boruta.Oauth.CodeRequest
  alias Boruta.Oauth.Error
  alias Boruta.Oauth.ResourceOwner
  alias Boruta.Oauth.Token

  def preauthorize(%CodeRequest{
        client_id: client_id,
        redirect_uri: redirect_uri,
        resource_owner: resource_owner,
        state: state,
        nonce: nonce,
        scope: scope,
        grant_type: grant_type,
        code_challenge: code_challenge,
        code_challenge_method: code_challenge_method
      }) do
    with {:ok, client} <-
           Authorization.Client.authorize(
             id: client_id,
             redirect_uri: redirect_uri,
             grant_type: grant_type
           ),
         {:ok, %ResourceOwner{sub: sub} = resource_owner} <-
           Authorization.ResourceOwner.authorize(resource_owner: resource_owner),
         {:ok, scope} <-
           Authorization.Scope.authorize(
             scope: scope,
             against: %{client: client, resource_owner: resource_owner}
           ) do
      case check_code_challenge(client, code_challenge, code_challenge_method) do
        :ok ->
          {:ok,
           %AuthorizationSuccess{
             client: client,
             redirect_uri: redirect_uri,
             sub: sub,
             scope: scope,
             state: state,
             nonce: nonce,
             code_challenge: code_challenge,
             code_challenge_method: code_challenge_method
           }}

        {:error, :invalid_code_challenge} ->
          {:error,
           %Error{
             status: :bad_request,
             error: :invalid_request,
             error_description: "Code challenge is invalid."
           }}
      end
    end
  end

  def token(request) do
    with {:ok,
          %AuthorizationSuccess{
            client: client,
            redirect_uri: redirect_uri,
            sub: sub,
            scope: scope,
            state: state,
            nonce: nonce,
            code_challenge: code_challenge,
            code_challenge_method: code_challenge_method
          }} <-
           preauthorize(request) do
      # TODO rescue from creation errors
      with {:ok, code} <-
             CodesAdapter.create(%{
               client: client,
               redirect_uri: redirect_uri,
               sub: sub,
               scope: scope,
               state: state,
               nonce: nonce,
               code_challenge: code_challenge,
               code_challenge_method: code_challenge_method
             }) do
        {:ok, %{code: code}}
      end
    end
  end

  @spec check_code_challenge(
          client :: Client.t(),
          code_challenge :: String.t(),
          code_challenge_method :: String.t()
        ) :: :ok | {:error, :invalid_code_challenge}
  defp check_code_challenge(%Client{pkce: false}, _code_challenge, _code_challenge_method),
    do: :ok

  defp check_code_challenge(%Client{pkce: true}, "", _code_challenge_method),
    do: {:error, :invalid_code_challenge}

  defp check_code_challenge(%Client{pkce: true}, nil, _code_challenge_method),
    do: {:error, :invalid_code_challenge}

  defp check_code_challenge(%Client{pkce: true}, _code_challenge, _code_challenge_method), do: :ok
end

defimpl Boruta.Oauth.Authorization, for: Boruta.Oauth.HybridRequest do
  import Boruta.Config, only: [access_tokens: 0, codes: 0, token_generator: 0]

  alias Boruta.Oauth.Authorization
  alias Boruta.Oauth.AuthorizationSuccess
  alias Boruta.Oauth.CodeRequest
  alias Boruta.Oauth.HybridRequest
  alias Boruta.Oauth.Error
  alias Boruta.Oauth.Scope
  alias Boruta.Oauth.Token

  def preauthorize(%HybridRequest{response_types: response_types} = request) do
    with {:ok, authorization} <-
           Authorization.preauthorize(struct(CodeRequest, Map.from_struct(request))) do
      {:ok, %{authorization | response_types: response_types}}
    end
  end

  def token(request) do
    with {:ok,
          %AuthorizationSuccess{
            response_types: response_types,
            client: client,
            redirect_uri: redirect_uri,
            sub: sub,
            scope: scope,
            state: state,
            nonce: nonce,
            code_challenge: code_challenge,
            code_challenge_method: code_challenge_method
          }} <-
           preauthorize(request) do
      Enum.reduce(response_types, {:ok, %{}}, fn
        "code", {:ok, tokens} ->
          with {:ok, code} <-
                 codes().create(%{
                   client: client,
                   redirect_uri: redirect_uri,
                   sub: sub,
                   scope: scope,
                   state: state,
                   nonce: nonce,
                   code_challenge: code_challenge,
                   code_challenge_method: code_challenge_method
                 }) do
            {:ok, Map.put(tokens, :code, code)}
          end

        "id_token", {:ok, tokens} ->
          case String.match?(scope, ~r/#{Scope.openid().name}/) do
            true ->
              token = tokens[:code] || %Token{
                type: "id_token",
                redirect_uri: redirect_uri,
                client: client,
                sub: sub,
                scope: scope,
                state: state,
                nonce: nonce,
                inserted_at: DateTime.utc_now()
              }

              id_token = %{token | value: token_generator().generate(:id_token, token)}

              {:ok, Map.put(tokens, :id_token, id_token)}

            false ->
              {:ok, tokens}
          end

        "token", {:ok, tokens} ->
          with {:ok, access_token} <-
                 access_tokens().create(
                   %{
                     client: client,
                     redirect_uri: redirect_uri,
                     sub: sub,
                     scope: scope,
                     state: state
                   },
                   refresh_token: false
                 ) do
            {:ok, Map.put(tokens, :token, access_token)}
          end

        _, _ ->
          {:error,
           %Error{
             error: :internal_server_error,
             error_description: "An error occured during token creation."
           }}
      end)
    end
  end
end

defimpl Boruta.Oauth.Authorization, for: Boruta.Oauth.RefreshTokenRequest do
  alias Boruta.AccessTokensAdapter
  alias Boruta.Oauth.Authorization
  alias Boruta.Oauth.AuthorizationSuccess
  alias Boruta.Oauth.Error
  alias Boruta.Oauth.RefreshTokenRequest
  alias Boruta.Oauth.Token

  def preauthorize(%RefreshTokenRequest{
        client_id: client_id,
        client_secret: client_secret,
        refresh_token: refresh_token,
        scope: scope,
        grant_type: grant_type
      }) do
    with {:ok, client} <-
           Authorization.Client.authorize(
             id: client_id,
             secret: client_secret,
             grant_type: grant_type
           ),
         {:ok,
          %Token{
            client: ^client,
            sub: sub
          } = token} <- Authorization.AccessToken.authorize(refresh_token: refresh_token),
         {:ok, scope} <- Authorization.Scope.authorize(scope: scope, against: %{token: token}) do
      {:ok, %AuthorizationSuccess{client: client, sub: sub, scope: scope}}
    else
      {:ok, _token} ->
        {:error,
         %Error{
           status: :bad_request,
           error: :invalid_grant,
           error_description: "Given refresh token is invalid."
         }}

      error ->
        error
    end
  end

  def token(request) do
    with {:ok, %AuthorizationSuccess{client: client, sub: sub, scope: scope}} <-
           preauthorize(request) do
      # TODO rescue from creation errors
      with {:ok, access_token} <-
             AccessTokensAdapter.create(
               %{
                 client: client,
                 sub: sub,
                 scope: scope
               },
               refresh_token: true
             ) do
        {:ok, %{token: access_token}}
      end
    end
  end
end
