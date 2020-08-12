table! {
    bridges (id) {
        id -> Integer,
        email -> Text,
        scope -> Text,
        cert_id -> Integer,
        cas_id -> Integer,
    }
}

table! {
    cacerts (id) {
        id -> Integer,
        priv_cert -> Text,
        ca_id -> Integer,
    }
}

table! {
    cas (id) {
        id -> Integer,
        domainname -> Text,
    }
}

table! {
    certs (id) {
        id -> Integer,
        fingerprint -> Text,
        pub_cert -> Text,
        user_id -> Nullable<Integer>,
    }
}

table! {
    certs_emails (id) {
        id -> Integer,
        addr -> Text,
        cert_id -> Integer,
    }
}

table! {
    revocations (id) {
        id -> Integer,
        hash -> Text,
        revocation -> Text,
        published -> Bool,
        cert_id -> Integer,
    }
}

table! {
    users (id) {
        id -> Integer,
        name -> Nullable<Text>,
        ca_id -> Integer,
    }
}

joinable!(bridges -> cas (cas_id));
joinable!(bridges -> certs (cert_id));
joinable!(cacerts -> cas (ca_id));
joinable!(certs -> users (user_id));
joinable!(certs_emails -> certs (cert_id));
joinable!(revocations -> certs (cert_id));
joinable!(users -> cas (ca_id));

allow_tables_to_appear_in_same_query!(
    bridges,
    cacerts,
    cas,
    certs,
    certs_emails,
    revocations,
    users,
);
