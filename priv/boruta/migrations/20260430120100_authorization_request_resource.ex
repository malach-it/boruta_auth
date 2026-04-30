defmodule Boruta.Migrations.AuthorizationRequestResource do
  @moduledoc false

  defmacro __using__(_args) do
    quote do
      def change do
        alter table(:authorization_requests) do
          add :resource, :string
        end
      end
    end
  end
end
