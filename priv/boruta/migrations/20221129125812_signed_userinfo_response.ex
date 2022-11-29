defmodule Boruta.Migrations.SignedUserinfoResponse do
  @moduledoc false

  defmacro __using__(_args) do
    quote do
      def change do

        # 20221129094553_add_userinfo_signed_response_alg_to_oauth_clients.exs
        alter table(:oauth_clients) do
          add :userinfo_signed_response_alg, :string
        end
      end
    end
  end
end
