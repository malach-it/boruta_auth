defmodule Boruta.Ecto.AdminTest do
  use Boruta.DataCase

  import Boruta.Factory
  import Ecto.Query, only: [from: 2]

  alias Boruta.Ecto.Admin
  alias Boruta.Ecto.Client
  alias Boruta.Ecto.Scope
  alias Boruta.Ecto.Token
  alias Boruta.Oauth.IdToken
  alias Boruta.Repo

  @client_valid_attrs %{
    redirect_uri: ["https://redirect.uri"]
  }
  @client_update_attrs %{
    redirect_uri: ["https://updated.redirect.uri"]
  }

  # clients
  def client_fixture(attrs \\ %{}) do
    {:ok, client} =
      attrs
      |> Enum.into(@client_valid_attrs)
      |> Admin.create_client()

    client
  end

  describe "list_clients/0" do
    test "returns all clients" do
      client = client_fixture()
      assert Admin.list_clients() == [client]
    end
  end

  describe "get_client/1" do
    test "returns the client with given id" do
      client = client_fixture()
      assert Admin.get_client!(client.id) == client
    end
  end

  describe "create_client/1" do
    test "returns error changeset with invalid redirect_uri (bad URI format)" do
      assert {:error, %Ecto.Changeset{}} =
               Admin.create_client(%{
                 redirect_uris: ["\\bad_redirect_uri"]
               })
    end

    test "returns an error when access token tll is invalid" do
      assert {:error, %Ecto.Changeset{}} =
               Admin.create_client(Map.put(@client_valid_attrs, :access_token_ttl, 1_000_000))
    end

    test "returns an error when authorization code tll is invalid" do
      assert {:error, %Ecto.Changeset{}} =
               Admin.create_client(
                 Map.put(@client_valid_attrs, :authorization_code_ttl, 1_000_000)
               )
    end

    test "creates a client with a given id" do
      id = SecureRandom.uuid()

      assert {:ok, %Client{id: ^id}} = Admin.create_client(%{id: id})
    end

    test "return an error if id already exists" do
      id = SecureRandom.uuid()

      assert {:ok, %Client{id: ^id}} = Admin.create_client(%{id: id})
      assert {:error, %Ecto.Changeset{}} = Admin.create_client(%{id: id})
    end

    test "return an error if id is invalid" do
      id = "not an uuid"

      assert {:error, %Ecto.Changeset{}} = Admin.create_client(%{id: id})
    end

    test "returns an error if given grant types are invalid" do
      assert {:error, %Ecto.Changeset{}} =
               Admin.create_client(
                 Map.merge(@client_valid_attrs, %{supported_grant_types: ["unknown"]})
               )
    end

    test "creates a client" do
      assert {:ok, %Client{}} = Admin.create_client(@client_valid_attrs)
    end

    test "creates a client with supproted_grant_types" do
      assert {:ok, %Client{supported_grant_types: ["client_credentials"]}} =
               Admin.create_client(
                 Map.merge(@client_valid_attrs, %{supported_grant_types: ["client_credentials"]})
               )
    end

    test "creates a client with a secret" do
      {:ok, %Client{secret: secret}} = Admin.create_client(@client_valid_attrs)
      assert secret
    end

    test "creates a client with a given secret" do
      secret = SecureRandom.hex(64)

      assert {:ok, %Client{secret: ^secret}} = Admin.create_client(%{secret: secret})
    end

    test "creates a client with default token ttls" do
      {:ok,
       %Client{
         access_token_ttl: access_token_ttl,
         authorization_code_ttl: authorization_code_ttl,
         refresh_token_ttl: refresh_token_ttl,
         id_token_ttl: id_token_ttl
       }} = Admin.create_client(@client_valid_attrs)

      assert access_token_ttl
      assert authorization_code_ttl
      assert refresh_token_ttl
      assert id_token_ttl
    end

    test "creates a client with token ttls" do
      {:ok,
       %Client{
         access_token_ttl: access_token_ttl,
         authorization_code_ttl: authorization_code_ttl,
         refresh_token_ttl: refresh_token_ttl,
         id_token_ttl: id_token_ttl
       }} =
        Admin.create_client(
          Map.merge(@client_valid_attrs, %{
            access_token_ttl: 1,
            authorization_code_ttl: 1,
            refresh_token_ttl: 1,
            id_token_ttl: 1
          })
        )

      assert access_token_ttl == 1
      assert authorization_code_ttl == 1
      assert refresh_token_ttl == 1
      assert id_token_ttl == 1
    end

    test "creates a client with authorized scopes by id" do
      scope = insert(:scope)

      assert {:ok, %Client{authorized_scopes: authorized_scopes}} =
               Admin.create_client(
                 Map.put(@client_valid_attrs, :authorized_scopes, [%{"id" => scope.id}])
               )

      assert authorized_scopes == [scope]
    end

    test "creates a client with authorized scopes by name" do
      scope = insert(:scope)

      assert {:ok, %Client{authorized_scopes: authorized_scopes}} =
               Admin.create_client(
                 Map.put(@client_valid_attrs, :authorized_scopes, [%{"name" => scope.name}])
               )

      assert authorized_scopes == [scope]
    end

    test "creates a client with authorized scopes by name (creates a scope)" do
      assert {:ok, %Client{authorized_scopes: authorized_scopes}} =
               Admin.create_client(
                 Map.put(@client_valid_attrs, :authorized_scopes, [%{"name" => "new:scope"}])
               )

      assert [%Scope{name: "new:scope"}] = authorized_scopes
    end

    test "creates a client with authorized scopes by name (invalid name)" do
      assert {:ok, %Client{authorized_scopes: authorized_scopes}} =
               Admin.create_client(
                 Map.put(@client_valid_attrs, :authorized_scopes, [%{"name" => "invalid scope"}])
               )

      assert [] = authorized_scopes
    end

    test "creates a client with key pair" do
      assert {:ok, %Client{public_key: pem_public_key, private_key: pem_private_key}} =
               Admin.create_client(@client_valid_attrs)

      message = "message"
      [public_entry] = :public_key.pem_decode(pem_public_key)
      [private_entry] = :public_key.pem_decode(pem_private_key)
      public_key = :public_key.pem_entry_decode(public_entry)
      private_key = :public_key.pem_entry_decode(private_entry)

      cipher_text = :public_key.encrypt_private(message, private_key)
      assert :public_key.decrypt_public(cipher_text, public_key) == message
    end

    test "creates a client with default id token signature alg" do
      assert {:ok, %Client{id_token_signature_alg: "RS512"}} =
               Admin.create_client(@client_valid_attrs)
    end

    test "returns an error with bad id token signature alg" do
      assert {:error, %Ecto.Changeset{}} =
               Admin.create_client(
                 Map.put(@client_valid_attrs, :id_token_signature_alg, "bad_alg")
               )
    end

    test "creates a client with id token signature alg" do
      Enum.map(IdToken.signature_algorithms(), fn alg ->
        assert {:ok, client} =
                 Admin.create_client(
                   Map.put(@client_valid_attrs, :id_token_signature_alg, Atom.to_string(alg))
                 )

        assert client.id_token_signature_alg == Atom.to_string(alg)
      end)
    end
  end

  describe "update_client/2" do
    test "returns error changeset with invalid redirect_uri (bad URI format)" do
      client = client_fixture()

      assert {:error, %Ecto.Changeset{}} =
               Admin.update_client(client, %{
                 redirect_uris: ["$bad_redirect_uri"]
               })

      assert client == Admin.get_client!(client.id)
    end

    test "retuns an error with a bad id token signature alg" do
      client = client_fixture()
      assert {:error, %Ecto.Changeset{}} =
               Admin.update_client(
                 client,
                 Map.put(@client_update_attrs, :id_token_signature_alg, "bad_alg")
               )
    end

    test "updates the client with an id token signature alg" do
      client = client_fixture()

      Enum.map(IdToken.signature_algorithms(), fn alg ->
        assert {:ok, client} =
                 Admin.update_client(
                   client,
                   Map.put(@client_update_attrs, :id_token_signature_alg, Atom.to_string(alg))
                 )

        assert client.id_token_signature_alg == Atom.to_string(alg)
      end)
    end

    test "updates the client" do
      client = client_fixture()
      assert {:ok, %Client{}} = Admin.update_client(client, @client_update_attrs)
    end

    test "updates the client with authorized scopes" do
      scope = insert(:scope)
      client = client_fixture()

      assert {:ok, %Client{authorized_scopes: authorized_scopes}} =
               Admin.update_client(client, %{"authorized_scopes" => [%{"id" => scope.id}]})

      assert authorized_scopes == [scope]
    end
  end

  describe "regenerate_client_secret/1" do
    test "regenerates client secret" do
      client = client_fixture()
      secret = client.secret

      assert {:ok, %Client{secret: new_secret}} = Admin.regenerate_client_secret(client)
      refute new_secret == secret
    end

    test "regenerates client secret given a secret" do
      client = client_fixture()
      secret = client.secret
      new_secret = "new_secret"

      assert {:ok, %Client{secret: ^new_secret}} =
               Admin.regenerate_client_secret(client, new_secret)

      refute new_secret == secret
    end
  end

  describe "regenerate_client_secret/1,2" do
    test "regenerates a client secret" do
      %Client{secret: secret} = client = client_fixture()

      assert {:ok, %Client{secret: new_secret}} = Admin.regenerate_client_secret(client)

      assert secret != new_secret

      assert %Client{secret: new_secret} = Repo.reload(client)

      assert secret != new_secret
    end

    test "updates a client secret" do
      secret = "a_secret"
      client = client_fixture()

      assert {:ok, %Client{secret: ^secret}} = Admin.regenerate_client_secret(client, secret)

      assert %Client{secret: ^secret} = Repo.reload(client)
    end
  end

  describe "delete_client/1" do
    test "deletes the client" do
      client = client_fixture()
      assert {:ok, %Client{}} = Admin.delete_client(client)
      assert_raise Ecto.NoResultsError, fn -> Admin.get_client!(client.id) end
    end
  end

  # scopes
  @scope_valid_attrs %{name: "some:name", public: true}
  @scope_update_attrs %{name: "some:updated:name", public: false}

  def scope_fixture(attrs \\ %{}) do
    {:ok, scope} =
      attrs
      |> Enum.into(%{name: SecureRandom.hex(64)})
      |> Admin.create_scope()

    scope
  end

  describe "list_scopes/0" do
    test "returns all scopes" do
      scope = scope_fixture()
      assert Admin.list_scopes() == [scope]
    end
  end

  describe "get_scope/1" do
    test "returns the scope with given id" do
      scope = scope_fixture()
      assert Admin.get_scope!(scope.id) == scope
    end
  end

  describe "get_scopes_by_ids/1" do
    test "returns the scopes with given id" do
      scopes = [scope_fixture(), scope_fixture(), scope_fixture()]
      expected_scopes = Enum.take(scopes, 2)
      ids = Enum.map(expected_scopes, fn %Scope{id: id} -> id end)

      assert Admin.get_scopes_by_ids(ids) == expected_scopes
    end
  end

  describe "get_scopes_by_names/1" do
    test "returns the scopes with given id" do
      scopes = [scope_fixture(), scope_fixture(), scope_fixture()]
      expected_scopes = Enum.take(scopes, 2)
      names = Enum.map(expected_scopes, fn %Scope{name: name} -> name end)

      assert Admin.get_scopes_by_names(names) == expected_scopes
    end
  end

  describe "create_scope/1" do
    test "returns error changeset with name missing" do
      assert {:error, %Ecto.Changeset{}} = Admin.create_scope(%{name: nil})
      assert {:error, %Ecto.Changeset{}} = Admin.create_scope(%{name: ""})
    end

    test "returns error changeset with name containing whitespace" do
      assert {:error, %Ecto.Changeset{}} = Admin.create_scope(%{name: "name with whitespace"})
    end

    test "creates a scope" do
      assert {:ok, %Scope{} = scope} = Admin.create_scope(@scope_valid_attrs)
      assert scope.name == "some:name"
      assert scope.public == true
    end

    test "creates a scope with public default to false" do
      assert {:ok, %Scope{} = scope} = Admin.create_scope(%{name: "name"})
      assert scope.public == false
    end
  end

  describe "update_scope/2" do
    setup do
      scope = scope_fixture()
      {:ok, scope: scope}
    end

    test "returns error changeset with name missing", %{scope: scope} do
      assert {:error, %Ecto.Changeset{}} = Admin.update_scope(scope, %{name: nil})
      assert {:error, %Ecto.Changeset{}} = Admin.update_scope(scope, %{name: ""})
      assert scope == Admin.get_scope!(scope.id)
    end

    test "returns error changeset with name containing whitespace", %{scope: scope} do
      assert {:error, %Ecto.Changeset{}} =
               Admin.update_scope(scope, %{name: "name with whitespace"})
    end

    test "returns error changeset with public set to nil", %{scope: scope} do
      assert {:error, %Ecto.Changeset{}} = Admin.update_scope(scope, %{public: nil})
      assert scope == Admin.get_scope!(scope.id)
    end

    test "updates the scope", %{scope: scope} do
      assert {:ok, %Scope{} = scope} = Admin.update_scope(scope, @scope_update_attrs)
      assert scope.name == "some:updated:name"
      assert scope.public == false
    end
  end

  describe "delete_scope/1" do
    setup do
      scope = scope_fixture()
      {:ok, scope: scope}
    end

    test "deletes the scope" do
      scope = scope_fixture()
      assert {:ok, %Scope{}} = Admin.delete_scope(scope)
      assert_raise Ecto.NoResultsError, fn -> Admin.get_scope!(scope.id) end
    end
  end

  # tokens

  describe "list_active_tokens/0" do
    test "returns active tokens" do
      active_token = insert(:token, expires_at: :os.system_time(:seconds) + 10) |> Repo.reload()
      _expired_token = insert(:token, expires_at: :os.system_time(:seconds) - 10)

      _revoked_token =
        insert(:token, expires_at: :os.system_time(:seconds) + 10, revoked_at: DateTime.utc_now())

      assert Admin.list_active_tokens() == [active_token]
    end

    test "returns active tokens with a queryable" do
      active_token =
        insert(:token, expires_at: :os.system_time(:seconds) + 10, scope: "test") |> Repo.reload()

      _other_active_token =
        insert(:token, expires_at: :os.system_time(:seconds) + 10, scope: "other")

      _expired_token = insert(:token, expires_at: :os.system_time(:seconds) - 10)

      _revoked_token =
        insert(:token, expires_at: :os.system_time(:seconds) + 10, revoked_at: DateTime.utc_now())

      assert Admin.list_active_tokens(from t in Token, where: t.scope == "test") == [active_token]
    end
  end

  describe "delete_inactive_tokens/0,1" do
    test "deletes inactive tokens (no given date)" do
      now = :os.system_time(:second)

      _active_token = insert(:token, expires_at: now)
      _expired_token = insert(:token, expires_at: now - 1)

      _active_revoked_token =
        insert(:token, expires_at: now, revoked_at: DateTime.from_unix!(now))

      _expired_revoked_token =
        insert(:token, expires_at: now - 1, revoked_at: DateTime.from_unix!(now))

      assert Admin.delete_inactive_tokens() == {2, nil}
    end

    test "deletes inactive tokens" do
      now = :os.system_time(:second)

      _active_token = insert(:token, expires_at: now)
      _expired_token = insert(:token, expires_at: now - 1)

      _active_revoked_token =
        insert(:token, expires_at: now, revoked_at: DateTime.from_unix!(now))

      _expired_revoked_token =
        insert(:token, expires_at: now - 1, revoked_at: DateTime.from_unix!(now))

      assert Admin.delete_inactive_tokens(DateTime.from_unix!(now)) == {2, nil}
    end

    test "deletes inactive tokens until given date" do
      now = :os.system_time(:second)

      _active_token = insert(:token, expires_at: now)
      _expired_token = insert(:token, expires_at: now - 1)

      _active_revoked_token =
        insert(:token, expires_at: now, revoked_at: DateTime.from_unix!(now))

      _expired_revoked_token =
        insert(:token, expires_at: now - 1, revoked_at: DateTime.from_unix!(now))

      _past_expired_token = insert(:token, expires_at: now - 11)

      _past_expired_revoked_token =
        insert(:token, expires_at: now - 11, revoked_at: DateTime.from_unix!(now))

      past_datetime = DateTime.from_unix!(now) |> DateTime.add(-10, :second)
      assert Admin.delete_inactive_tokens(past_datetime) == {2, nil}
    end

    test "deletes inactive tokens until given future date" do
      now = :os.system_time(:second)

      _active_token = insert(:token, expires_at: now)
      _expired_token = insert(:token, expires_at: now - 1)

      _active_revoked_token =
        insert(:token, expires_at: now, revoked_at: DateTime.from_unix!(now))

      _expired_revoked_token =
        insert(:token, expires_at: now - 1, revoked_at: DateTime.from_unix!(now))

      _future_active_token = insert(:token, expires_at: now + 10)

      _future_active_revoked_token =
        insert(:token, expires_at: now + 10, revoked_at: DateTime.from_unix!(now))

      future_datetime = DateTime.from_unix!(now) |> DateTime.add(10, :second)

      assert Admin.delete_inactive_tokens(future_datetime) == {3, nil}
    end
  end
end
