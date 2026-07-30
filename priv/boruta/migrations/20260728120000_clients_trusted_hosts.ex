defmodule Boruta.Migrations.ClientsTrustedHosts do
  @moduledoc false

  defmacro __using__(_args) do
    quote do
      def change do
        alter table(:oauth_clients) do
          add(:trusted_hosts, {:array, :text}, default: nil)
        end
      end
    end
  end
end
