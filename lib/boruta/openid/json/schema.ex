defmodule Boruta.Openid.Json.Schema do
  @moduledoc false
  alias ExJsonSchema.Schema

  @uuid_pattern "\^[0-9a-fA-F]{8}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{12}\$"

  def credential do
    %{
      "type" => "object",
      "properties" => %{
        "format" => %{"type" => "string"},
        "proof" => %{
          "type" => "object",
          "properties" => %{
            "proof_type" => %{"type" => "string", "pattern" => "^jwt$"},
            "jwt" => %{"type" => "string"},
          },
          "required" => ["proof_type", "jwt"]
        },
        "credential_identifier" => %{"type" => "string"},
      },
      "required" => ["credential_identifier"]
    }
    |> Schema.resolve()
  end
end
