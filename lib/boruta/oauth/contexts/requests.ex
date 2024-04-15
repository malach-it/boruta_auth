defmodule Boruta.Oauth.Requests do
  @moduledoc """
  Request context
  """

  @doc """
  Persists an authorization request according to given params
  """
  @callback store_request(
              request :: Boruta.Oauth.AuthorizationRequest.t(),
              client :: Boruta.Oauth.Client.t()
            ) ::
              {:ok, request :: Boruta.Oauth.AuthorizationRequest.t()}
              | {:error, Ecto.Changeset.t()}
end
