defmodule Boruta.Repo.Migrations.AddUserinfoSignedResponseAlgToOauthClients do
  use Ecto.Migration

  def change do
    alter table(:oauth_clients) do
      add :userinfo_signed_response_alg, :string
    end
  end
end
