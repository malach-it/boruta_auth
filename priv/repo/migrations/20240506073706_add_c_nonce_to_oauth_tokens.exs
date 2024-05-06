defmodule Boruta.Repo.Migrations.AddCNonceToOauthTokens do
  use Ecto.Migration

  def change do
    alter table(:oauth_tokens) do
      add :c_nonce, :string
    end
  end
end
