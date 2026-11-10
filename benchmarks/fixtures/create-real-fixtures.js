const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

const fixturesRoot = path.join(__dirname, '..', 'fixtures');

const fixtures = [
  {
    name: 'real-vite-react',
    packageJson: {
      name: 'real-vite-react',
      version: '1.0.0',
      private: true,
      type: 'module',
      scripts: {
        test: "node -e \"console.log('vite-react ok')\""
      },
      dependencies: {
        react: '^18.3.1',
        'react-dom': '^18.3.1'
      },
      devDependencies: {
        '@vitejs/plugin-react': '^4.3.1',
        vite: '^5.3.4'
      }
    }
  },
  {
    name: 'real-nextjs',
    packageJson: {
      name: 'real-nextjs',
      version: '1.0.0',
      private: true,
      scripts: {
        test: "node -e \"console.log('nextjs ok')\""
      },
      dependencies: {
        next: '14.2.5',
        react: '^18.3.1',
        'react-dom': '^18.3.1'
      },
      devDependencies: {
        typescript: '^5.5.3'
      }
    }
  },
  {
    name: 'real-express-ts',
    packageJson: {
      name: 'real-express-ts',
      version: '1.0.0',
      private: true,
      scripts: {
        test: "node -e \"console.log('express-ts ok')\""
      },
      dependencies: {
        express: '^4.19.2'
      },
      devDependencies: {
        '@types/express': '^4.17.21',
        'ts-node': '^10.9.2',
        typescript: '^5.5.3'
      }
    }
  },
  {
    name: 'real-electron',
    packageJson: {
      name: 'real-electron',
      version: '1.0.0',
      private: true,
      scripts: {
        test: "node -e \"console.log('electron ok')\""
      },
      devDependencies: {
        electron: '^28.3.3'
      }
    }
  },
  {
    name: 'real-monorepo-workspaces',
    packageJson: {
      name: 'real-monorepo-workspaces',
      version: '1.0.0',
      private: true,
      workspaces: ['packages/*'],
      scripts: {
        test: "node -e \"console.log('monorepo ok')\""
      },
      devDependencies: {
        prettier: '^3.2.5'
      }
    },
    packages: [
      {
        subPath: 'packages/pkg-a',
        packageJson: {
          name: '@real-monorepo/pkg-a',
          version: '1.0.0',
          scripts: {
            test: "node -e \"console.log('pkg-a ok')\""
          },
          dependencies: {
            ms: '^2.1.3'
          }
        }
      },
      {
        subPath: 'packages/pkg-b',
        packageJson: {
          name: '@real-monorepo/pkg-b',
          version: '1.0.0',
          scripts: {
            test: "node -e \"console.log('pkg-b ok')\""
          },
          dependencies: {
            '@real-monorepo/pkg-a': '^1.0.0',
            chalk: '^4.1.2'
          }
        }
      }
    ]
  },
  {
    name: 'real-git-deps',
    packageJson: {
      name: 'real-git-deps',
      version: '1.0.0',
      private: true,
      scripts: {
        test: "node -e \"console.log('git-deps ok')\""
      },
      dependencies: {
        inherits: 'git+https://github.com/isaacs/inherits.git#v2.0.4'
      }
    }
  },
  {
    name: 'real-optional-platform',
    packageJson: {
      name: 'real-optional-platform',
      version: '1.0.0',
      private: true,
      scripts: {
        test: "node -e \"console.log('optional-platform ok')\""
      },
      dependencies: {
        esbuild: '^0.20.2',
        sharp: '^0.33.4'
      }
    }
  },
  {
    name: 'real-peer-conflicts',
    packageJson: {
      name: 'real-peer-conflicts',
      version: '1.0.0',
      private: true,
      scripts: {
        test: "node -e \"console.log('peer-conflicts ok')\""
      },
      dependencies: {
        '@testing-library/react-hooks': '^8.0.1',
        react: '^18.3.1',
        'react-dom': '^18.3.1'
      },
      overrides: {
        '@testing-library/react-hooks': {
          react: '$react',
          'react-dom': '$react-dom'
        }
      }
    }
  },
  {
    name: 'real-lifecycle-scripts',
    packageJson: {
      name: 'real-lifecycle-scripts',
      version: '1.0.0',
      private: true,
      scripts: {
        postinstall: "node -e \"console.log('lifecycle postinstall ok')\"",
        test: "node -e \"console.log('lifecycle test ok')\""
      },
      dependencies: {
        chalk: '^4.1.2'
      }
    }
  },
  {
    name: 'real-bundled-deps',
    packageJson: {
      name: 'real-bundled-deps',
      version: '1.0.0',
      private: true,
      scripts: {
        test: "node -e \"console.log('bundled-deps ok')\""
      },
      bundleDependencies: ['ms'],
      dependencies: {
        chalk: '^4.1.2',
        ms: '^2.1.3'
      }
    }
  }
];

for (const fix of fixtures) {
  const dir = path.join(fixturesRoot, fix.name);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
  fs.writeFileSync(
    path.join(dir, 'package.json'),
    JSON.stringify(fix.packageJson, null, 2) + '\n'
  );

  if (fix.packages) {
    for (const pkg of fix.packages) {
      const pdir = path.join(dir, pkg.subPath);
      if (!fs.existsSync(pdir)) {
        fs.mkdirSync(pdir, { recursive: true });
      }
      fs.writeFileSync(
        path.join(pdir, 'package.json'),
        JSON.stringify(pkg.packageJson, null, 2) + '\n'
      );
    }
  }

  console.log(`Generating package-lock.json for ${fix.name}...`);
  try {
    execSync('npm.cmd install --package-lock-only', {
      cwd: dir,
      stdio: 'inherit',
      env: { ...process.env, ELECTRON_SKIP_BINARY_DOWNLOAD: '1' }
    });
  } catch (err) {
    console.error(`Failed to generate lockfile for ${fix.name}:`, err.message);
    process.exit(1);
  }
}

console.log('All real-* fixtures created successfully!');
