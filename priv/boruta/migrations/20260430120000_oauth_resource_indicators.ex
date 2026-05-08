defmodule Boruta.Migrations.OauthResourceIndicators do
  @moduledoc false

  defmacro __using__(_args) do
    quote do
      def change do
        alter table(:oauth_tokens) do
          add(:resource, :text)
        end

        alter table(:authorization_requests) do
          add(:resource, :text)
        end

        alter table(:oauth_clients) do
          add(:authorized_resources, {:array, :text}, default: [], null: false)
        end
      end
    end
  end
end
