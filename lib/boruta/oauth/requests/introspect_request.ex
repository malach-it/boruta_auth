defmodule Boruta.Oauth.IntrospectRequest do
  @moduledoc """
  Introspect request
  """

  @typedoc """
  Type representing an introspect request as stated in [Introspect RFC](https://tools.ietf.org/html/rfc7662#section-2.1).
  """
  @type t :: %__MODULE__{
          client_id: String.t(),
          client_authentication: %{
            type: String.t(),
            value: String.t()
          },
          token: String.t()
        }
  @enforce_keys [:client_id, :client_authentication, :token]
  defstruct client_id: nil, client_authentication: nil, token: nil
end
