defprotocol Boruta.Oauth.Authorization do
  @moduledoc """
  """

  @doc """
  Creates and returns a token for given request, depending of implementation.
  """
  # TODO type check implementations
  def token(request)
end

defimpl Boruta.Oauth.Authorization, for: Boruta.Oauth.ClientCredentialsRequest do
  import Boruta.Config, only: [access_tokens: 0]

  alias Boruta.Oauth.Authorization
  alias Boruta.Oauth.ClientCredentialsRequest
  alias Boruta.Oauth.Token

  def token(%ClientCredentialsRequest{
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
      # TODO rescue from creation errors
      access_tokens().create(
        %{
          client: client,
          scope: scope
        },
        refresh_token: true
      )
    end
  end
end

defimpl Boruta.Oauth.Authorization, for: Boruta.Oauth.PasswordRequest do
  import Boruta.Config, only: [access_tokens: 0]

  alias Boruta.Oauth.Authorization
  alias Boruta.Oauth.PasswordRequest
  alias Boruta.Oauth.ResourceOwner
  alias Boruta.Oauth.Token

  def token(%PasswordRequest{
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
      # TODO rescue from creation errors
      access_tokens().create(
        %{
          client: client,
          sub: sub,
          scope: scope
        },
        refresh_token: true
      )
    end
  end
end

defimpl Boruta.Oauth.Authorization, for: Boruta.Oauth.AuthorizationCodeRequest do
  import Boruta.Config, only: [access_tokens: 0]

  alias Boruta.Oauth.Authorization
  alias Boruta.Oauth.AuthorizationCodeRequest
  alias Boruta.Oauth.ResourceOwner
  alias Boruta.Oauth.Token

  def token(%AuthorizationCodeRequest{
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
      # TODO rescue from creation errors
      access_tokens().create(
        %{
          client: client,
          redirect_uri: redirect_uri,
          sub: sub,
          scope: code.scope
        },
        refresh_token: true
      )
    end
  end
end

defimpl Boruta.Oauth.Authorization, for: Boruta.Oauth.TokenRequest do
  import Boruta.Config, only: [access_tokens: 0]

  alias Boruta.Oauth.Authorization
  alias Boruta.Oauth.ResourceOwner
  alias Boruta.Oauth.TokenRequest
  alias Boruta.Oauth.Token

  def token(%TokenRequest{
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
      # TODO rescue from creation errors
      access_tokens().create(
        %{
          client: client,
          redirect_uri: redirect_uri,
          sub: sub,
          scope: scope,
          state: state
        },
        refresh_token: false
      )
    end
  end
end

defimpl Boruta.Oauth.Authorization, for: Boruta.Oauth.CodeRequest do
  import Boruta.Config, only: [codes: 0]

  alias Boruta.Oauth.Authorization
  alias Boruta.Oauth.CodeRequest
  alias Boruta.Oauth.Error
  alias Boruta.Oauth.ResourceOwner
  alias Boruta.Oauth.Token

  def token(%CodeRequest{
        client_id: client_id,
        redirect_uri: redirect_uri,
        resource_owner: resource_owner,
        state: state,
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
         {:ok, %ResourceOwner{sub: sub}} <-
           Authorization.ResourceOwner.authorize(resource_owner: resource_owner),
         {:ok, scope} <-
           Authorization.Scope.authorize(
             scope: scope,
             against: %{client: client}
           ) do
      # TODO rescue from creation errors
      case codes().create(%{
             client: client,
             sub: sub,
             redirect_uri: redirect_uri,
             state: state,
             scope: scope,
             code_challenge: code_challenge,
             code_challenge_method: code_challenge_method
           }) do
        {:ok, token} ->
          {:ok, token}

        {:error, %Ecto.Changeset{errors: errors} = changeset} ->
          case errors[:code_challenge] == {"can't be blank", [validation: :required]} do
            true ->
              {:error,
               %Error{
                 status: :bad_request,
                 error: :invalid_request,
                 error_description: "Code challenge must be provided for PKCE requests."
               }}

            false ->
              {:error, changeset}
          end

        {:error, error} ->
          {:error, error}
      end
    end
  end
end

defimpl Boruta.Oauth.Authorization, for: Boruta.Oauth.RefreshTokenRequest do
  import Boruta.Config, only: [access_tokens: 0]

  alias Boruta.Oauth.Authorization
  alias Boruta.Oauth.RefreshTokenRequest
  alias Boruta.Oauth.Token

  def token(%RefreshTokenRequest{
        client_id: client_id,
        client_secret: client_secret,
        refresh_token: refresh_token,
        scope: scope,
        grant_type: grant_type
      }) do
    with {:ok, _} <-
           Authorization.Client.authorize(
             id: client_id,
             secret: client_secret,
             grant_type: grant_type
           ),
         {:ok,
          %Token{
            client: client,
            sub: sub
          } = token} <- Authorization.AccessToken.authorize(refresh_token: refresh_token),
         {:ok, scope} <- Authorization.Scope.authorize(scope: scope, against: %{token: token}) do
      # TODO rescue from creation errors
      access_tokens().create(
        %{
          client: client,
          sub: sub,
          scope: scope
        },
        refresh_token: true
      )
    end
  end
end
