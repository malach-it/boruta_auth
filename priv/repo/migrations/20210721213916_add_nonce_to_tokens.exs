defmodule Boruta.Repo.Migrations.AddNonceToTokens do
  use Ecto.Migration

  def change do
    alter table(:tokens) do
      add :nonce, :string
    end
  end
end
