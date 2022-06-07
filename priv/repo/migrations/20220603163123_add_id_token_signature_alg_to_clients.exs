defmodule Boruta.Repo.Migrations.AddIdTokenSignatureAlgToClients do
  use Ecto.Migration

  def change do
    alter table(:oauth_clients) do
      add :id_token_signature_alg, :string, default: "RS512"
    end
  end
end
