defmodule Boruta.Ecto.Requests do
  @moduledoc false
  @behaviour Boruta.Oauth.Requests

  import Boruta.Config, only: [repo: 0]
  import Boruta.Ecto.OauthMapper, only: [to_oauth_schema: 1]

  alias Boruta.Ecto.AuthorizationRequest

  @impl Boruta.Oauth.Requests
  def get_request(request_id) do
    case Ecto.UUID.cast(request_id) do
      {:ok, id} ->
        repo().get(AuthorizationRequest, id) |> to_oauth_schema()
      _ -> nil
    end
  end

  @impl Boruta.Oauth.Requests
  def store_request(request, client) do
    params = %{
      client_id: request.client_id,
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
