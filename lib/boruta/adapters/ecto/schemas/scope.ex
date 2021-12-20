defmodule Boruta.Ecto.Scope do
  @moduledoc """
  Ecto Adapter Scope Schema
  """

  use Ecto.Schema
  import Ecto.Changeset

  @type t :: %__MODULE__{
          name: String.t(),
          public: boolean()
        }

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id
  @timestamps_opts type: :utc_datetime
  schema "oauth_scopes" do
    field :name, :string, default: ""
    field :label, :string
    field :public, :boolean, default: false

    timestamps()
  end

  def changeset(scope, attrs) do
    scope
    |> cast(attrs, [:label, :name, :public])
    |> unique_constraint(:id)
    |> unique_constraint(:name)
    |> validate_required([:name])
    |> validate_not_nil(:public)
    |> validate_no_whitespace(:name)
  end

  def assoc_changeset(scope, attrs) do
    scope
    |> cast(attrs, [:id, :name])
    |> validate_no_whitespace(:name)
  end

  defp validate_not_nil(changeset, field) do
    if get_field(changeset, field) == nil do
      add_error(changeset, field, "must not be null")
    else
      changeset
    end
  end

  defp validate_no_whitespace(changeset, field) do
    value = get_field(changeset, field)

    if value && String.match?(value, ~r/\s/) do
      add_error(changeset, field, "must not contain whitespace")
    else
      changeset
    end
  end
end
