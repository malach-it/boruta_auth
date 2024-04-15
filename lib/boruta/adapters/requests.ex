defmodule Boruta.RequestsAdapter do
  @moduledoc """
  Encapsulate injected `Boruta.Oauth.Requests` adapter in context configuration
  """
  @behaviour Boruta.Oauth.Requests

  import Boruta.Config, only: [repo: 0]
  import Boruta.Ecto.OauthMapper, only: [to_oauth_schema: 1]

  alias Boruta.Ecto.AuthorizationRequest

  @impl Boruta.Oauth.Requests
  def store_request(request, client) do
    params = %{
      client_authentication: request.client_authentication,
      response_type: request.response_type,
      redirect_uri: request.redirect_uri,
      scope: request.scope,
      state: request.state,
      code_challenge: request.code_challenge,
      code_challenge_method: request.code_challenge_method
    }

    with {:ok, request} <-
           AuthorizationRequest.create_changeset(%AuthorizationRequest{}, params, client)
           |> repo().insert() do
      {:ok, to_oauth_schema(request)}
    end
  end
end
