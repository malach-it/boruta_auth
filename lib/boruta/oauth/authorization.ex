defprotocol Boruta.Oauth.Authorization do
  @moduledoc """
  OAuth requests authorization
  """

  @doc """
  Checks if request is valid for token creation for given request, depending of implementation.
  """
  @spec preauthorize(request :: any()) ::
          {:ok, Boruta.Oauth.AuthorizationSuccess.t()} | {:error, Boruta.Oauth.Error.t()}
  def preauthorize(request)

  @doc """
  Creates and returns tokens for given request, depending of implementation.
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
  Struct encapsulating an authorization success data
  """

  @enforce_keys [:client, :scope]
  defstruct response_types: [],
            public_client_id: nil,
            client: nil,
            redirect_uri: nil,
            resource_owner: nil,
            sub: nil,
            scope: nil,
            state: nil,
            nonce: nil,
            access_token: nil,
            code: nil,
            code_challenge: nil,
            code_challenge_method: nil,
            authorization_details: nil,
            presentation_definition: nil,
            issuer: nil,
            response_mode: nil,
            agent_token: nil,
            bind_data: nil,
            bind_configuration: nil

  @type t :: %__MODULE__{
          response_types: list(String.t()),
          client: Boruta.Oauth.Client.t(),
          public_client_id: String.t(),
          access_token: Boruta.Oauth.Token.t() | nil,
          code: Boruta.Oauth.Token.t() | nil,
          redirect_uri: String.t() | nil,
          sub: String.t() | nil,
          resource_owner: Boruta.Oauth.ResourceOwner.t() | nil,
          scope: String.t(),
          state: String.t() | nil,
          nonce: String.t() | nil,
          code_challenge: String.t() | nil,
          code_challenge_method: String.t() | nil,
          authorization_details: list(map()) | nil,
          presentation_definition: map() | nil,
          issuer: String.t() | nil,
          response_mode: String.t() | nil,
          agent_token: String.t() | nil,
          bind_data: map(),
          bind_configuration: map()
        }
end

defimpl Boruta.Oauth.Authorization, for: Boruta.Oauth.ClientCredentialsRequest do
  alias Boruta.AccessTokensAdapter
  alias Boruta.Dpop
  alias Boruta.Oauth.Authorization
  alias Boruta.Oauth.AuthorizationSuccess
  alias Boruta.Oauth.ClientCredentialsRequest
  alias Boruta.Oauth.Token

  def preauthorize(%ClientCredentialsRequest{
        client_id: client_id,
        client_authentication: client_source,
        scope: scope,
        grant_type: grant_type,
        dpop: dpop
      }) do
    with {:ok, client} <-
           Authorization.Client.authorize(
             id: client_id,
             source: client_source,
             grant_type: grant_type
           ),
         :ok <- Dpop.validate(dpop, client),
         {:ok, scope} <- Authorization.Scope.authorize(scope: scope, against: %{client: client}) do
      {:ok, %AuthorizationSuccess{client: client, scope: scope}}
    end
  end

  def token(request) do
    with {:ok, %AuthorizationSuccess{client: client, scope: scope}} <- preauthorize(request) do
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

defimpl Boruta.Oauth.Authorization, for: Boruta.Oauth.AgentCredentialsRequest do
  alias Boruta.AgentTokensAdapter
  alias Boruta.Dpop
  alias Boruta.Oauth.Authorization
  alias Boruta.Oauth.AuthorizationSuccess
  alias Boruta.Oauth.AgentCredentialsRequest
  alias Boruta.Oauth.Token

  def preauthorize(%AgentCredentialsRequest{
        client_id: client_id,
        client_authentication: client_source,
        scope: scope,
        grant_type: grant_type,
        dpop: dpop,
        bind_data: bind_data,
        bind_configuration: bind_configuration
      }) do
    with {:ok, client} <-
           Authorization.Client.authorize(
             id: client_id,
             source: client_source,
             grant_type: grant_type
           ),
         :ok <- Dpop.validate(dpop, client),
         {:ok, scope} <- Authorization.Scope.authorize(scope: scope, against: %{client: client}),
         {:ok, bind_data, bind_configuration} <-
           Authorization.Data.authorize(bind_data, bind_configuration) do
      {:ok,
       %AuthorizationSuccess{
         client: client,
         scope: scope,
         bind_data: bind_data,
         bind_configuration: bind_configuration
       }}
    end
  end

  def token(request) do
    with {:ok,
          %AuthorizationSuccess{
            client: client,
            scope: scope,
            bind_data: bind_data,
            bind_configuration: bind_configuration
          }} <- preauthorize(request) do
      with {:ok, agent_token} <-
             AgentTokensAdapter.create(
               %{
                 client: client,
                 scope: scope,
                 bind_data: bind_data,
                 bind_configuration: bind_configuration
               },
               refresh_token: true
             ) do
        {:ok, %{agent_token: agent_token}}
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
        client_authentication: client_source,
        username: username,
        password: password,
        scope: scope,
        grant_type: grant_type
      }) do
    with {:ok, client} <-
           Authorization.Client.authorize(
             id: client_id,
             source: client_source,
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
  alias Boruta.AccessTokensAdapter
  alias Boruta.CodesAdapter
  alias Boruta.Dpop
  alias Boruta.Oauth.Authorization
  alias Boruta.Oauth.AuthorizationCodeRequest
  alias Boruta.Oauth.AuthorizationSuccess
  alias Boruta.Oauth.Client
  alias Boruta.Oauth.IdToken
  alias Boruta.Oauth.ResourceOwner
  alias Boruta.Oauth.Scope
  alias Boruta.Oauth.Token

  def preauthorize(%AuthorizationCodeRequest{
        client_id: client_id,
        client_authentication: client_source,
        code: code,
        redirect_uri: redirect_uri,
        grant_type: grant_type,
        code_verifier: code_verifier,
        dpop: dpop
      }) do
    # TODO check client did against request from code phase in case of siopv2 requests
    with {:ok, client} <-
           Authorization.Client.authorize(
             id: client_id,
             source: client_source,
             redirect_uri: redirect_uri,
             grant_type: grant_type,
             code_verifier: code_verifier
           ),
         :ok <- Dpop.validate(dpop, client),
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
         nonce: code.nonce,
         authorization_details: code.authorization_details
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
            nonce: nonce,
            authorization_details: authorization_details
          }} <-
           preauthorize(request),
         {:ok, access_token} <-
           AccessTokensAdapter.create(
             %{
               client: client,
               redirect_uri: redirect_uri,
               previous_code: code.value,
               sub: sub,
               scope: scope,
               authorization_details: authorization_details
             },
             refresh_token: true
           ),
         {:ok, _code} <- CodesAdapter.revoke(code) do
      # TODO check if from an hybrid request
      case {Client.public?(client), String.match?(scope, ~r/#{Scope.openid().name}/)} do
        {true, _} ->
          {:ok, %{token: access_token}}

        {_, true} ->
          id_token = IdToken.generate(%{token: access_token}, nonce)

          {:ok, %{token: access_token, id_token: id_token}}

        {_, false} ->
          {:ok, %{token: access_token}}
      end
    end
  end
end

defimpl Boruta.Oauth.Authorization, for: Boruta.Oauth.AgentCodeRequest do
  alias Boruta.AgentTokensAdapter
  alias Boruta.CodesAdapter
  alias Boruta.Dpop
  alias Boruta.Oauth.Authorization
  alias Boruta.Oauth.AgentCodeRequest
  alias Boruta.Oauth.AuthorizationSuccess
  alias Boruta.Oauth.Client
  alias Boruta.Oauth.IdToken
  alias Boruta.Oauth.ResourceOwner
  alias Boruta.Oauth.Scope
  alias Boruta.Oauth.Token

  def preauthorize(%AgentCodeRequest{
        client_id: client_id,
        client_authentication: client_source,
        code: code,
        redirect_uri: redirect_uri,
        grant_type: grant_type,
        code_verifier: code_verifier,
        dpop: dpop,
        bind_data: bind_data,
        bind_configuration: bind_configuration
      }) do
    # TODO check client did against request from code phase in case of siopv2 requests
    with {:ok, client} <-
           Authorization.Client.authorize(
             id: client_id,
             source: client_source,
             redirect_uri: redirect_uri,
             grant_type: grant_type,
             code_verifier: code_verifier
           ),
         :ok <- Dpop.validate(dpop, client),
         {:ok, code} <-
           Authorization.Code.authorize(%{
             value: code,
             redirect_uri: redirect_uri,
             client: client,
             code_verifier: code_verifier
           }),
         {:ok, %ResourceOwner{sub: sub} = resource_owner} <-
           Authorization.ResourceOwner.authorize(resource_owner: code.resource_owner),
         {:ok, bind_data, bind_configuration} <-
           Authorization.Data.authorize(bind_data, bind_configuration, resource_owner) do
      {:ok,
       %AuthorizationSuccess{
         client: client,
         code: code,
         redirect_uri: redirect_uri,
         sub: sub,
         scope: code.scope,
         nonce: code.nonce,
         authorization_details: code.authorization_details,
         bind_data: bind_data,
         bind_configuration: bind_configuration,
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
            nonce: nonce,
            authorization_details: authorization_details,
            bind_data: bind_data,
            bind_configuration: bind_configuration,
          }} <-
           preauthorize(request),
         {:ok, agent_token} <-
           AgentTokensAdapter.create(
             %{
               client: client,
               redirect_uri: redirect_uri,
               previous_code: code.value,
               sub: sub,
               scope: scope,
               authorization_details: authorization_details,
               bind_data: bind_data,
               bind_configuration: bind_configuration
             },
             refresh_token: true
           ),
         {:ok, _code} <- CodesAdapter.revoke(code) do
      # TODO check if from an hybrid request
      case {Client.public?(client), String.match?(scope, ~r/#{Scope.openid().name}/)} do
        {true, _} ->
          {:ok, %{agent_token: agent_token}}

        {_, true} ->
          id_token = IdToken.generate(%{token: agent_token}, nonce)

          {:ok, %{agent_token: agent_token, id_token: id_token}}

        {_, false} ->
          {:ok, %{agent_token: agent_token}}
      end
    end
  end
end

defimpl Boruta.Oauth.Authorization, for: Boruta.Oauth.PreauthorizationCodeRequest do
  alias Boruta.Oauth.Client
  alias Boruta.AccessTokensAdapter
  alias Boruta.CodesAdapter
  alias Boruta.Oauth.Authorization
  alias Boruta.Oauth.PreauthorizationCodeRequest
  alias Boruta.Oauth.AuthorizationSuccess
  alias Boruta.Oauth.Error
  alias Boruta.Oauth.IdToken
  alias Boruta.Oauth.ResourceOwner
  alias Boruta.Oauth.Scope
  alias Boruta.Oauth.Token

  def preauthorize(%PreauthorizationCodeRequest{
        preauthorized_code: preauthorized_code,
        tx_code: tx_code
      }) do
    with {:ok, code} <-
           Authorization.Code.authorize(%{
             value: preauthorized_code
           }),
         :ok <- maybe_check_tx_code(tx_code, code),
         {:ok, %ResourceOwner{sub: sub}} <-
           (case code.agent_token do
             nil ->
               Authorization.ResourceOwner.authorize(resource_owner: code.resource_owner)
             _ ->
               {:ok, code.resource_owner}
           end) do
      {:ok,
       %AuthorizationSuccess{
         client: code.client,
         code: code,
         sub: sub,
         scope: code.scope,
         nonce: code.nonce,
         authorization_details: code.authorization_details,
         agent_token: code.agent_token
       }}
    end
  end

  def token(request) do
    with {:ok,
          %AuthorizationSuccess{
            client: client,
            code: code,
            sub: sub,
            scope: scope,
            nonce: nonce,
            authorization_details: authorization_details,
            agent_token: agent_token
          }} <-
           preauthorize(request),
         {:ok, access_token} <-
           AccessTokensAdapter.create(
             %{
               client: client,
               previous_code: code.value,
               sub: sub,
               scope: scope,
               authorization_details: authorization_details,
               agent_token: agent_token
             },
             refresh_token: true
           ),
         {:ok, _code} <- CodesAdapter.revoke(code) do
      case String.match?(scope, ~r/#{Scope.openid().name}/) do
        true ->
          id_token = IdToken.generate(%{token: access_token}, nonce)

          {:ok, %{preauthorized_token: access_token, id_token: id_token}}

        false ->
          {:ok, %{preauthorized_token: access_token}}
      end
    end
  end

  defp maybe_check_tx_code(tx_code, %Token{
         client: %Client{enforce_tx_code: true},
         tx_code: against_tx_code
       }) do
    case tx_code == against_tx_code do
      true ->
        :ok

      false ->
        {:error,
         %Error{
           status: :bad_request,
           error: :invalid_request,
           error_description: "Given transaction code is invalid."
         }}
    end
  end

  defp maybe_check_tx_code(_tx_code, _preauthorized_code), do: :ok
end

defimpl Boruta.Oauth.Authorization, for: Boruta.Oauth.TokenRequest do
  alias Boruta.AccessTokensAdapter
  alias Boruta.Oauth.Authorization
  alias Boruta.Oauth.AuthorizationSuccess
  alias Boruta.Oauth.IdToken
  alias Boruta.Oauth.ResourceOwner
  alias Boruta.Oauth.Scope
  alias Boruta.Oauth.Token
  alias Boruta.Oauth.TokenRequest

  def preauthorize(
        %TokenRequest{
          response_types: response_types,
          client_id: client_id,
          redirect_uri: redirect_uri,
          resource_owner: resource_owner,
          state: state,
          nonce: nonce,
          scope: scope,
          grant_type: grant_type
        } = request
      ) do
    with {:ok, client} <-
           Authorization.Client.authorize(
             id: client_id,
             source: nil,
             redirect_uri: redirect_uri,
             grant_type: grant_type
           ),
         {:ok, %ResourceOwner{sub: sub}} <-
           Authorization.ResourceOwner.authorize(resource_owner: resource_owner),
         {:ok, scope} <-
           Authorization.Scope.authorize(
             scope: scope,
             against: %{client: client, resource_owner: resource_owner}
           ),
         :ok <- Authorization.Nonce.authorize(request) do
      {:ok,
       %AuthorizationSuccess{
         response_types: response_types,
         resource_owner: resource_owner,
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
            resource_owner: resource_owner,
            client: client,
            redirect_uri: redirect_uri,
            sub: sub,
            scope: scope,
            state: state,
            nonce: nonce
          }} <- preauthorize(request) do
      response_types
      |> Enum.sort_by(fn response_type -> response_type == "id_token" end)
      |> Enum.reduce({:ok, %{}}, fn
        "id_token", {:ok, tokens} when tokens == %{} ->
          case String.match?(scope, ~r/#{Scope.openid().name}/) do
            true ->
              base_token = %Token{
                type: "base_token",
                client: client,
                resource_owner: resource_owner,
                redirect_uri: redirect_uri,
                sub: sub,
                scope: scope,
                state: state,
                inserted_at: DateTime.utc_now()
              }

              id_token = IdToken.generate(%{base_token: base_token}, nonce)
              {:ok, %{id_token: id_token}}

            false ->
              {:ok, %{}}
          end

        "id_token", {:ok, tokens} ->
          case String.match?(scope, ~r/#{Scope.openid().name}/) do
            true ->
              id_token = IdToken.generate(tokens, nonce)
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
                     state: state,
                     resource_owner: resource_owner
                   },
                   refresh_token: false
                 ) do
            {:ok, Map.put(tokens, :token, access_token)}
          end
      end)
    end
  end
end

defimpl Boruta.Oauth.Authorization, for: Boruta.Oauth.PreauthorizedCodeRequest do
  alias Boruta.PreauthorizedCodesAdapter
  alias Boruta.Oauth.Authorization
  alias Boruta.Oauth.AuthorizationSuccess
  alias Boruta.Oauth.Client
  alias Boruta.Oauth.CodeRequest
  alias Boruta.Oauth.Error
  alias Boruta.Oauth.PreauthorizedCodeRequest
  alias Boruta.Oauth.ResourceOwner
  alias Boruta.Oauth.Token

  def preauthorize(%PreauthorizedCodeRequest{
        agent_token: agent_token,
        client_id: client_id,
        redirect_uri: redirect_uri,
        resource_owner: resource_owner,
        state: state,
        scope: scope,
        grant_type: grant_type
      }) do
    with {:ok, client} <-
           Authorization.Client.authorize(
             id: client_id,
             source: nil,
             redirect_uri: redirect_uri,
             grant_type: grant_type
           ),
         {:ok, %ResourceOwner{sub: sub} = resource_owner} <-
           (case agent_token do
              nil ->
                Authorization.ResourceOwner.authorize(resource_owner: resource_owner)

              agent_token ->
                Authorization.AgentToken.authorize(
                  agent_token: agent_token,
                  resource_owner: resource_owner
                )
            end),
         {:ok, scope} <-
           Authorization.Scope.authorize(
             scope: scope,
             against: %{client: client, resource_owner: resource_owner}
           ) do
      {:ok,
       %AuthorizationSuccess{
         client: client,
         redirect_uri: redirect_uri,
         sub: sub,
         scope: scope,
         state: state,
         resource_owner: resource_owner,
         agent_token: agent_token
       }}
    else
      {:error, :invalid_code_challenge} ->
        {:error,
         %Error{
           status: :bad_request,
           error: :invalid_request,
           error_description: "Code challenge is invalid."
         }}

      error ->
        error
    end
  end

  def token(request) do
    with {:ok,
          %AuthorizationSuccess{
            client: client,
            resource_owner: resource_owner,
            redirect_uri: redirect_uri,
            sub: sub,
            scope: scope,
            state: state,
            nonce: nonce,
            agent_token: agent_token
          }} <-
           preauthorize(request) do
      # TODO create a preauthorized code
      with {:ok, preauthorized_code} <-
             PreauthorizedCodesAdapter.create(%{
               client: client,
               resource_owner: resource_owner,
               redirect_uri: redirect_uri,
               sub: sub,
               scope: scope,
               state: state,
               nonce: nonce,
               agent_token: agent_token
             }) do
        {:ok, %{preauthorized_code: preauthorized_code}}
      end
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
  alias Boruta.Openid.VerifiableCredentials

  def preauthorize(
        %CodeRequest{
          client_id: client_id,
          redirect_uri: redirect_uri,
          resource_owner: resource_owner,
          state: state,
          nonce: nonce,
          scope: scope,
          code_challenge: code_challenge,
          code_challenge_method: code_challenge_method,
          authorization_details: authorization_details
        } = request
      ) do
    with {:ok, client} <-
           Authorization.Client.authorize(
             id: client_id,
             source: nil,
             redirect_uri: redirect_uri,
             # in order to differentiate code from authorization_code requests
             grant_type: "code"
           ),
         {:ok, %ResourceOwner{sub: sub} = resource_owner} <-
           Authorization.ResourceOwner.authorize(resource_owner: resource_owner),
         {:ok, scope} <-
           Authorization.Scope.authorize(
             scope: scope,
             against: %{client: client, resource_owner: resource_owner}
           ),
         :ok <- Authorization.Nonce.authorize(request),
         :ok <- VerifiableCredentials.validate_authorization_details(authorization_details),
         :ok <- check_code_challenge(client, code_challenge, code_challenge_method) do
      {:ok,
       %AuthorizationSuccess{
         client: client,
         redirect_uri: redirect_uri,
         sub: sub,
         scope: scope,
         state: state,
         nonce: nonce,
         code_challenge: code_challenge,
         code_challenge_method: code_challenge_method,
         resource_owner: resource_owner,
         authorization_details: Jason.decode!(authorization_details)
       }}
    else
      {:error, :invalid_code_challenge} ->
        {:error,
         %Error{
           status: :bad_request,
           error: :invalid_request,
           error_description: "Code challenge is invalid."
         }}

      error ->
        error
    end
  end

  def token(request) do
    with {:ok,
          %AuthorizationSuccess{
            client: client,
            resource_owner: resource_owner,
            redirect_uri: redirect_uri,
            sub: sub,
            scope: scope,
            state: state,
            nonce: nonce,
            code_challenge: code_challenge,
            code_challenge_method: code_challenge_method,
            authorization_details: authorization_details
          }} <-
           preauthorize(request) do
      with {:ok, code} <-
             CodesAdapter.create(%{
               client: client,
               resource_owner: resource_owner,
               redirect_uri: redirect_uri,
               sub: sub,
               scope: scope,
               state: state,
               nonce: nonce,
               code_challenge: code_challenge,
               code_challenge_method: code_challenge_method,
               authorization_details: authorization_details
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

defimpl Boruta.Oauth.Authorization, for: Boruta.Oauth.AuthorizationRequest do
  alias Boruta.CodesAdapter
  alias Boruta.Oauth.Authorization
  alias Boruta.Oauth.AuthorizationRequest
  alias Boruta.Oauth.AuthorizationSuccess
  alias Boruta.Oauth.Client
  alias Boruta.Oauth.CodeRequest
  alias Boruta.Oauth.Error
  alias Boruta.Oauth.Token
  alias Boruta.Openid.VerifiableCredentials

  def preauthorize(%AuthorizationRequest{
        client_id: client_id,
        client_authentication: client_authentication,
        redirect_uri: redirect_uri,
        state: state,
        scope: scope,
        code_challenge: code_challenge,
        code_challenge_method: code_challenge_method
      }) do
    with {:ok, client} <-
           Authorization.Client.authorize(
             id: client_id,
             source: client_authentication,
             redirect_uri: redirect_uri,
             # in order to differentiate code from authorization_code requests
             grant_type: "code"
           ),
         {:ok, scope} <-
           Authorization.Scope.authorize(
             scope: scope,
             against: %{client: client}
           ),
         :ok <- check_code_challenge(client, code_challenge, code_challenge_method) do
      {:ok,
       %AuthorizationSuccess{
         client: client,
         redirect_uri: redirect_uri,
         scope: scope,
         state: state,
         code_challenge: code_challenge,
         code_challenge_method: code_challenge_method
       }}
    else
      {:error, :invalid_code_challenge} ->
        {:error,
         %Error{
           status: :bad_request,
           error: :invalid_request,
           error_description: "Code challenge is invalid."
         }}

      error ->
        error
    end
  end

  def token(_params), do: raise("Not implemented")

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

defimpl Boruta.Oauth.Authorization, for: Boruta.Oauth.PresentationRequest do
  alias Boruta.ClientsAdapter
  alias Boruta.CodesAdapter
  alias Boruta.Oauth.Authorization
  alias Boruta.Oauth.AuthorizationSuccess
  alias Boruta.Oauth.CodeRequest
  alias Boruta.Oauth.Error
  alias Boruta.Oauth.PresentationRequest
  alias Boruta.Oauth.Token
  alias Boruta.Openid.VerifiableCredentials
  alias Boruta.Openid.VerifiablePresentations

  def preauthorize(
        %PresentationRequest{
          client_id: client_id,
          resource_owner: resource_owner,
          redirect_uri: redirect_uri,
          state: state,
          nonce: nonce,
          scope: scope,
          code_challenge: code_challenge,
          code_challenge_method: code_challenge_method,
          authorization_details: authorization_details,
          client_metadata: client_metadata,
          response_type: response_type
        } = request
      ) do
    with [response_type] = response_types <-
           VerifiablePresentations.response_types(
             response_type,
             scope,
             resource_owner.presentation_configuration
           ),
         {:ok, client} <-
           (case client_id do
              "did:" <> _key ->
               {:ok, ClientsAdapter.public!()}

              _ ->
                Authorization.Client.authorize(
                  id: client_id,
                  source: nil,
                  redirect_uri: redirect_uri,
                  grant_type: response_type
                )
            end),
         {:ok, resource_owner} <-
           (case client_id do
              "did:" <> _key -> {:ok, resource_owner}
              _ -> Authorization.ResourceOwner.authorize(resource_owner: resource_owner)
            end),
         {:ok, scope} <-
           Authorization.Scope.authorize(
             scope: scope,
             against: %{client: client}
           ),
         :ok <- Authorization.Nonce.authorize(request),
         :ok <- VerifiableCredentials.validate_authorization_details(authorization_details),
         :ok <- VerifiablePresentations.check_client_metadata(client_metadata),
         presentation_definition <-
           VerifiablePresentations.presentation_definition(
             resource_owner.presentation_configuration,
             scope
           ) do

      {code_challenge, code_challenge_method} = case resource_owner.code_verifier do
        nil -> {code_challenge, code_challenge_method}
        code_verifier -> {code_verifier , "plain"}
      end

      {:ok,
       %AuthorizationSuccess{
         response_types: response_types,
         presentation_definition: presentation_definition,
         redirect_uri: redirect_uri,
         public_client_id: client_id,
         client: client,
         sub: resource_owner.sub,
         scope: scope,
         state: state,
         nonce: nonce,
         code_challenge: code_challenge,
         code_challenge_method: code_challenge_method,
         authorization_details: Jason.decode!(authorization_details),
         response_mode: client.response_mode
       }}
    else
      {:error, :invalid_code_challenge} ->
        {:error,
         %Error{
           status: :bad_request,
           error: :invalid_request,
           error_description: "Code challenge is invalid."
         }}

      error ->
        error
    end
  end

  def token(request) do
    with {:ok,
          %AuthorizationSuccess{
            response_types: response_types,
            presentation_definition: presentation_definition,
            redirect_uri: redirect_uri,
            public_client_id: public_client_id,
            client: client,
            sub: sub,
            scope: scope,
            state: state,
            nonce: nonce,
            code_challenge: code_challenge,
            code_challenge_method: code_challenge_method,
            authorization_details: authorization_details,
            response_mode: response_mode
          }} <-
           preauthorize(request) do
      with {:ok, code} <-
             CodesAdapter.create(%{
               client: client,
               public_client_id: public_client_id,
               redirect_uri: redirect_uri,
               sub: sub,
               scope: scope,
               state: state,
               nonce: nonce,
               code_challenge: code_challenge,
               code_challenge_method: code_challenge_method,
               authorization_details: authorization_details,
               presentation_definition: presentation_definition
             }) do
        case response_types do
          ["id_token"] ->
            {:ok, %{siopv2_code: code, response_mode: response_mode}}

          ["vp_token"] ->
            {:ok, %{vp_code: code, response_mode: response_mode}}
        end
      end
    end
  end
end

defimpl Boruta.Oauth.Authorization, for: Boruta.Oauth.HybridRequest do
  alias Boruta.AccessTokensAdapter
  alias Boruta.CodesAdapter
  alias Boruta.Oauth.Authorization
  alias Boruta.Oauth.AuthorizationSuccess
  alias Boruta.Oauth.CodeRequest
  alias Boruta.Oauth.Error
  alias Boruta.Oauth.HybridRequest
  alias Boruta.Oauth.IdToken
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
            resource_owner: resource_owner,
            redirect_uri: redirect_uri,
            sub: sub,
            scope: scope,
            state: state,
            nonce: nonce,
            code_challenge: code_challenge,
            code_challenge_method: code_challenge_method,
            authorization_details: authorization_details
          }} <-
           preauthorize(request) do
      response_types
      |> Enum.sort_by(fn response_type -> response_type == "id_token" end)
      |> Enum.reduce({:ok, %{}}, fn
        "code", {:ok, tokens} when tokens == %{} ->
          with {:ok, code} <-
                 CodesAdapter.create(%{
                   client: client,
                   resource_owner: resource_owner,
                   redirect_uri: redirect_uri,
                   sub: sub,
                   scope: scope,
                   state: state,
                   nonce: nonce,
                   code_challenge: code_challenge,
                   code_challenge_method: code_challenge_method,
                   authorization_details: authorization_details
                 }) do
            {:ok, Map.put(tokens, :code, code)}
          end

        "id_token", {:ok, tokens} ->
          case String.match?(scope, ~r/#{Scope.openid().name}/) do
            true ->
              id_token = IdToken.generate(tokens, nonce)

              {:ok, Map.put(tokens, :id_token, id_token)}

            false ->
              {:ok, tokens}
          end

        "token", {:ok, tokens} ->
          with {:ok, access_token} <-
                 AccessTokensAdapter.create(
                   %{
                     client: client,
                     resource_owner: resource_owner,
                     redirect_uri: redirect_uri,
                     sub: sub,
                     scope: scope,
                     state: state
                   },
                   refresh_token: false
                 ) do
            {:ok, Map.put(tokens, :token, access_token)}
          end

        _, {:error, error} ->
          {:error,
           %Error{
             status: :internal_server_error,
             error: :unknown_error,
             error_description: "An error occurred during token creation: #{inspect(error)}."
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
        client_authentication: client_source,
        refresh_token: refresh_token,
        scope: scope,
        grant_type: grant_type
      }) do
    with {:ok, client} <-
           Authorization.Client.authorize(
             id: client_id,
             source: client_source,
             grant_type: grant_type
           ),
         {:ok,
          %Token{
            client: ^client,
            sub: sub,
            scope: token_scope
          } = token} <- Authorization.AccessToken.authorize(refresh_token: refresh_token),
         {:ok, scope} <-
           Authorization.Scope.authorize(scope: scope || token_scope, against: %{token: token}) do
      {:ok, %AuthorizationSuccess{client: client, sub: sub, scope: scope, access_token: token}}
    else
      {:ok, _token} ->
        {:error,
         %Error{
           status: :bad_request,
           error: :invalid_grant,
           error_description: "Given refresh token is invalid, revoked, or expired."
         }}

      error ->
        error
    end
  end

  def token(request) do
    with {:ok,
          %AuthorizationSuccess{
            client: client,
            sub: sub,
            scope: scope,
            access_token: previous_token
          }} <-
           preauthorize(request) do
      with {:ok, access_token} <-
             AccessTokensAdapter.create(
               %{
                 previous_token: previous_token.value,
                 client: client,
                 sub: sub,
                 scope: scope
               },
               refresh_token: true
             ),
           {:ok, _token} <- AccessTokensAdapter.revoke_refresh_token(previous_token) do
        {:ok, %{token: access_token}}
      end
    end
  end
end
