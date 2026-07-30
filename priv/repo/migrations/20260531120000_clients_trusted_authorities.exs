defmodule Boruta.Repo.Migrations.ClientsTrustedAuthorities do
  use Ecto.Migration

  def change do
    alter table(:oauth_clients) do
      add(:trusted_authorities, :text, default: "", null: false)
    end
  end
end
