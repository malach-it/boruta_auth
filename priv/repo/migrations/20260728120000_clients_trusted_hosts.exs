defmodule Boruta.Repo.Migrations.ClientsTrustedHosts do
  use Ecto.Migration

  def change do
    alter table(:oauth_clients) do
      add(:trusted_hosts, {:array, :text}, default: nil)
    end
  end
end
