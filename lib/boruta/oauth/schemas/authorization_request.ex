defmodule Boruta.Oauth.AuthorizationRequest do
  @moduledoc """
  Authorization request and utilities
  """

  defstruct id: nil,
            client_id: nil,
            client_authentication: %{},
            response_type: nil,
            redirect_uri: nil,
            scope: nil,
            state: nil,
            code_challenge: nil,
            code_challenge_method: nil,
            expires_at: nil

  @type client_authentication :: %{
          client_id: String.t(),
          credentials: %{
            String.t() => String.t()
          }
        }

  @type t :: %__MODULE__{
          id: String.t(),
          client_id: String.t(),
          client_authentication: client_authentication(),
          response_type: String.t(),
          redirect_uri: String.t(),
          scope: String.t(),
          state: String.t(),
          code_challenge: String.t(),
          code_challenge_method: String.t(),
          expires_at: integer()
        }

  def persisted?(%__MODULE__{id: nil}), do: false
  def persisted?(_request), do: true
end
