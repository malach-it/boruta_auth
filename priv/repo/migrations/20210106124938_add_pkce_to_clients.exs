defmodule Boruta.Repo.Migrations.AddPkceToClients do
  use Ecto.Migration

  def change do
    alter table(:clients) do
      add(:pkce, :boolean, default: false)
    end

    alter table(:tokens) do
      add(:code_challenge_hash, :string)
      add(:code_challenge_method, :string)
    end
  end
end
