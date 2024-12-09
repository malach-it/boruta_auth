defmodule Boruta.Repo.Migrations.AddTxCodeToTokens do
  use Ecto.Migration

  def change do
    alter table(:oauth_tokens) do
      add :tx_code, :string
    end

    alter table(:oauth_clients) do
      add :enforce_tx_code, :boolean, null: false, default: false
    end
  end
end
