// Explicit refresh only. The gate never downloads or silently changes its inputs.
import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';

const root = path.dirname(fileURLToPath(import.meta.url));
const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
const published = {
  frameworks: ['next', 'nuxt', '@remix-run/react', 'astro', '@sveltejs/kit', '@angular/core', 'vue', '@nestjs/core', 'electron', 'react-native', 'expo', 'express', 'fastify', 'koa', 'hapi', 'svelte', 'react', 'react-dom', 'preact', 'solid-js', 'lit', 'alpinejs', 'gatsby', '@angular/cli', '@nestjs/cli'],
  tooling: ['webpack', 'webpack-cli', 'rollup', '@babel/core', '@babel/cli', 'eslint', 'typescript-eslint', 'typescript', 'jest', 'vitest', '@playwright/test', 'storybook', 'prisma', '@prisma/client', 'vite', 'parcel', 'esbuild', '@swc/core', 'tsup', 'tsx', 'postcss', 'tailwindcss', 'sass', 'less', 'prettier'],
  libraries: ['axios', 'got', 'undici', 'chalk', 'commander', 'yargs', 'inquirer', 'ora', 'winston', 'pino', 'debug', 'dotenv', 'zod', 'joi', 'ajv', 'lodash', 'ramda', 'rxjs', '@tanstack/react-query', '@reduxjs/toolkit', 'react-router', 'react-hook-form', '@mui/material', '@emotion/react', 'antd'],
  native: ['sharp', 'bcrypt', 'sqlite3', 'better-sqlite3', 'canvas', 'argon2', 'node-sass', 'node-pty', 'utf-8-validate', 'bufferutil', 'lmdb', 'level', 'snappy', 'isolated-vm', 'keytar'],
  packaging: ['npm', 'pnpm', 'yarn', 'npm-check-updates', 'pacote', '@npmcli/arborist', 'cacache', 'tar', 'node-gyp', 'prebuild-install'],
};
const index = { imported: new Date().toISOString(), description: 'Unmodified package/package.json files extracted from pinned public npm tarballs. These are published development manifests, not generated dependency-only consumers.', projects: [] };
for (const [category, names] of Object.entries(published)) {
  for (const name of names) {
    const url = `https://registry.npmjs.org/${encodeURIComponent(name)}/latest`;
    const response = await fetch(url);
    if (!response.ok) throw new Error(`${url}: ${response.status}`);
    const metadata = await response.json();
    const tarResponse = await fetch(metadata.dist.tarball);
    if (!tarResponse.ok) throw new Error(`${metadata.dist.tarball}: ${tarResponse.status}`);
    const tarball = Buffer.from(await tarResponse.arrayBuffer());
    const manifest = execFileSync('tar', ['-xzOf', '-', 'package/package.json'], { input: tarball, maxBuffer: 16 * 1024 * 1024 });
    JSON.parse(manifest.toString());
    const id = name.replace(/^@/, '').replaceAll('/', '-');
    const relative = `published/${id}/package.json`;
    fs.mkdirSync(path.join(root, 'published', id), { recursive: true });
    fs.writeFileSync(path.join(root, relative), manifest);
    const source = { package: name, version: metadata.version, source: `https://registry.npmjs.org/${encodeURIComponent(name)}/${metadata.version}`,
      tarball: metadata.dist.tarball, integrity: metadata.dist.integrity, tarball_sha256: sha256(tarball), date: index.imported };
    index.projects.push({ id, category, kind: 'published-manifest', source,
      files: { 'package.json': { path: relative, sha256: sha256(manifest) } } });
    fs.writeFileSync(path.join(root, 'index.json'), JSON.stringify(index, null, 2) + '\n');
    console.log(`${index.projects.length}: ${name}@${metadata.version}`);
  }
}
console.log(`Pinned ${index.projects.length} unmodified published manifests`);
