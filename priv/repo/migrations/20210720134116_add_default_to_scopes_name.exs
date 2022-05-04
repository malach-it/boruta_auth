defmodule Boruta.Repo.Migrations.AddDefaultToScopesName do
  use Ecto.Migration

  def up do
    alter table(:scopes) do
      modify :name, :string, default: ""
    end
  end

  def down do
    alter table(:scopes) do
      modify :name, :string
    end
  end
end
