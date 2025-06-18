defmodule Boruta.Oauth.Requests do
  @moduledoc """
  Request context
  """

  @doc """
  Get an authorization request according to given id
  """
  @callback get_request(request_id :: String.t()) ::
              request :: Boruta.Oauth.AuthorizationRequest.t() | nil

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
