defmodule Boruta.Repo.Migrations.AddDefaultToTokensScope do
  use Ecto.Migration

  def up do
    alter table(:tokens) do
      modify :scope, :string, default: ""
    end
  end

  def down do
    alter table(:tokens) do
      modify :scope, :string
    end
  end
end
