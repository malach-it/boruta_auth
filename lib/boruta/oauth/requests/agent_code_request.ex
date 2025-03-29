defmodule Boruta.Oauth.AgentCodeRequest do
  @moduledoc """
  Agent code request
  """

  @typedoc """
  Type representing an agent code request
  """
  @type t :: %__MODULE__{
          client_id: String.t(),
          client_authentication: %{
            type: String.t(),
            value: String.t()
          },
          redirect_uri: String.t(),
          code: String.t(),
          grant_type: String.t(),
          code_verifier: String.t(),
          dpop: Boruta.Dpop.t(),
          bind_data: String.t(),
          bind_configuration: String.t()
        }
  @enforce_keys [:client_id, :redirect_uri, :code]
  defstruct client_id: nil,
            client_authentication: nil,
            redirect_uri: nil,
            code: nil,
            grant_type: "agent_code",
            code_verifier: "",
            dpop: nil,
            bind_data: nil,
            bind_configuration: nil
end
