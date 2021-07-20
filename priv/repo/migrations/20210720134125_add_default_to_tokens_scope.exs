defmodule Boruta.Repo.Migrations.AddDefaultToTokensScope do
  use Ecto.Migration

  def change do
    alter table(:tokens) do
      modify :scope, :string, default: ""
    end
  end
end
