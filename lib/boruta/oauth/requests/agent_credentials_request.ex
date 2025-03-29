defmodule Boruta.Oauth.AgentCredentialsRequest do
  @moduledoc """
  Agent credentials request
  """

  @typedoc """
  Type representing a agent credentials request. This grant type enables to bind data to an agent token aimed to be shared to access the according data
  """
  @type t :: %__MODULE__{
          client_id: String.t(),
          client_authentication: %{
            type: String.t(),
            value: String.t()
          },
          scope: String.t(),
          grant_type: String.t(),
          dpop: Boruta.Dpop.t() | nil,
          bind_data: String.t(),
          bind_configuration: String.t()
        }
  @enforce_keys [:client_id, :client_authentication]
  defstruct client_id: nil,
            client_authentication: nil,
            scope: "",
            grant_type: "agent_credentials",
            dpop: nil,
            bind_data: "",
            bind_configuration: ""
end
