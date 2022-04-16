defmodule Boruta.Oauth.TokenRequest do
  @moduledoc """
  Implicit request
  """

  @typedoc """
  Type representing an implicit request as stated in [OAuth 2.0 RFC](https://tools.ietf.org/html/rfc6749#section-4.2.1) and [OpenId Connect core 1.0](https://openid.net/specs/openid-connect-core-1_0.html#ImplicitFlowAuth)

  Note : `resource_owner` is an addition that must be provided by the application layer.
  """
  @type t :: %__MODULE__{
          response_types: list(String.t()),
          client_id: String.t(),
          redirect_uri: String.t(),
          state: String.t(),
          scope: String.t(),
          resource_owner: struct(),
          grant_type: String.t(),
          nonce: String.t()
        }
  @enforce_keys [:client_id, :redirect_uri, :resource_owner]
  defstruct client_id: nil,
            redirect_uri: nil,
            state: "",
            scope: "",
            resource_owner: nil,
            grant_type: "implicit",
            nonce: nil,
            response_types: [],
            prompt: ""

  alias Boruta.Oauth.Scope

  @spec require_nonce?(request :: __MODULE__.t()) :: boolean()
  def require_nonce?(%__MODULE__{response_types: response_types, scope: scope}) do
    Scope.contains_openid?(scope) &&
      Enum.member?(response_types, "id_token")
  end
end
