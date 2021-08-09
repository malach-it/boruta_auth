defmodule Boruta.Repo.Migrations.AddDefaultToScopesName do
  use Ecto.Migration

  def change do
    alter table(:scopes) do
      modify :name, :string, default: ""
    end
  end
end
