defmodule Boruta.Ecto.AuthorizationRequest do
  @moduledoc """
  Ecto Adapter Request Schema
  """

  use Ecto.Schema

  import Ecto.Changeset

  @type t :: %__MODULE__{
          id: String.t(),
          client_id: String.t(),
          client_authentication: map(),
          response_type: String.t(),
          redirect_uri: String.t(),
          scope: String.t(),
          state: String.t(),
          code_challenge: String.t(),
          code_challenge_method: String.t(),
          expires_at: integer(),
          inserted_at: DateTime.t(),
          updated_at: DateTime.t()
        }

  @primary_key {:id, Ecto.UUID, autogenerate: true}
  @foreign_key_type :binary_id
  @timestamps_opts type: :utc_datetime
  schema "authorization_requests" do
    field :client_id, :string
    field :client_authentication, :map
    field :response_type, :string
    field :redirect_uri, :string
    field :scope, :string
    field :state, :string
    field :code_challenge, :string
    field :code_challenge_method, :string
    field :expires_at, :integer

    timestamps()
  end

  def create_changeset(request, attrs, client) do
    request
    |> cast(attrs, [
      :client_id,
      :client_authentication,
      :response_type,
      :redirect_uri,
      :scope,
      :state,
      :code_challenge,
      :code_challenge_method,
      :expires_at
    ])
    |> put_time_to_live(client)
  end

  defp put_time_to_live(changeset, client) do
    expires_at = :os.system_time(:seconds) + client.authorization_request_ttl

    change(changeset, %{expires_at: expires_at})
  end
end
