defmodule Boruta.Repo.Migrations.AddSignaturesAdapterToOauthClients do
  use Ecto.Migration

  def change do
    alter table(:oauth_clients) do
      add :signatures_adapter, :string, null: false, default: "Elixir.Boruta.Internal.Signatures"
    end
  end
end
