defmodule Boruta.Ecto.Credential do
  @moduledoc """
  Ecto Adapter Credential Schema
  """

  use Ecto.Schema

  import Ecto.Changeset

  @type t :: %__MODULE__{
          id: String.t(),
          credential: String.t(),
          format: String.t(),
          defered: boolean(),
          access_token: String.t(),
          inserted_at: DateTime.t(),
          updated_at: DateTime.t()
        }

  @primary_key {:id, Ecto.UUID, autogenerate: true}
  @foreign_key_type :binary_id
  @timestamps_opts type: :utc_datetime
  schema "ssi_credentials" do
    field :credential, :string
    field :format, :string
    field :access_token, :string
    field :defered, :boolean

    timestamps()
  end

  def create_changeset(credential, attrs) do
    credential
    |> cast(attrs, [
      :credential,
      :format,
      :defered,
      :access_token
    ])
  end
end
