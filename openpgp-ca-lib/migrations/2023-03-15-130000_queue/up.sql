-- SPDX-FileCopyrightText: 2023 Heiko Schaefer <heiko@schaefer.name>
-- SPDX-License-Identifier: GPL-3.0-or-later
--
-- This file is part of OpenPGP CA
-- https://gitlab.com/openpgp-ca/openpgp-ca
--

-- Add "queue" table for split mode operations

-- Queue for split mode operations
CREATE TABLE queue (
  id INTEGER NOT NULL PRIMARY KEY,
  created TIMESTAMP NOT NULL,
  task VARCHAR NOT NULL,
  done BOOLEAN NOT NULL
);
