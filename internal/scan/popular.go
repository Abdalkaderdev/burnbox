package scan

import "strings"

var popularNPM = set(`react react-dom lodash express axios chalk commander debug moment request typescript webpack
vue vuex jquery underscore async uuid yargs dotenv body-parser cors mongoose mongodb mysql mysql2 redis
socket.io jsonwebtoken bcrypt bcryptjs nodemon eslint prettier jest mocha chai sinon ts-node rxjs next nuxt
svelte vite rollup esbuild glob minimist semver fs-extra rimraf mkdirp colors inquirer node-fetch
cross-env cross-spawn classnames prop-types styled-components tailwindcss postcss autoprefixer sass less
dayjs date-fns luxon validator joi yup zod ajv cookie-parser express-session passport multer morgan winston
pino helmet compression nodemailer sequelize prisma knex graphql apollo-server puppeteer playwright cheerio
sharp electron chokidar execa superagent form-data formidable busboy handlebars marked highlight.js three
chart.js socket.io-client react-router react-router-dom redux react-redux mobx immer zustand typeorm ethers
web3 bignumber.js crypto-js node-forge xml2js js-yaml yaml ramda bluebird gulp grunt browserify karma jasmine
cypress vitest husky lint-staged concurrently npm-run-all serve http-server live-server stripe aws-sdk firebase
discord.js telegraf openai langchain tslib core-js regenerator-runtime isomorphic-fetch cross-fetch nanoid
shortid faker left-pad request-promise ua-parser-js event-stream angular moment-timezone object-assign
inherits safe-buffer source-map string-width strip-ansi ansi-styles supports-color readable-stream
preact color fastify koa yarn pnpm npm iconv-lite graceful-fs signal-exit escape-string-regexp micromatch picomatch fast-glob`)

var popularPyPI = set(`requests numpy pandas django flask urllib3 setuptools boto3 botocore six python-dateutil
pyyaml certifi idna charset-normalizer cryptography pytest jinja2 markupsafe click attrs pillow scipy
matplotlib sqlalchemy psycopg2 psycopg2-binary beautifulsoup4 lxml selenium tensorflow torch scikit-learn
fastapi uvicorn pydantic aiohttp httpx colorama tqdm rich paramiko pymongo redis celery gunicorn werkzeug
openai transformers opencv-python pyjwt bcrypt pycryptodome docutils packaging wheel virtualenv black flake8
mypy pylint isort coverage simplejson ujson toml tomli protobuf grpcio websocket-client websockets pyserial
discord.py python-dotenv arrow pendulum pytz tzdata babel nltk spacy keras xgboost lightgbm seaborn plotly
streamlit gradio langchain anthropic tiktoken pyopenssl jmespath s3transfer pyasn1 rsa`)

func set(words string) map[string]bool {
	m := map[string]bool{}
	for _, w := range strings.Fields(words) {
		m[w] = true
	}
	return m
}

func typosquat(name string, popular map[string]bool) string {
	if popular[name] || strings.HasPrefix(name, "@") || len(name) < 4 {
		return ""
	}
	best := ""
	for p := range popular {
		if len(p) >= 5 && oneEdit(name, p) && (best == "" || p < best) {
			best = p
		}
	}
	return best
}

func oneEdit(a, b string) bool {
	if a == b {
		return false
	}
	la, lb := len(a), len(b)
	if la-lb > 1 || lb-la > 1 {
		return false
	}
	i := 0
	for i < la && i < lb && a[i] == b[i] {
		i++
	}
	switch {
	case la == lb:
		if a[i+1:] == b[i+1:] {
			return true
		}
		return i+1 < la && a[i] == b[i+1] && a[i+1] == b[i] && a[i+2:] == b[i+2:]
	case la > lb:
		return a[i+1:] == b[i:]
	default:
		return a[i:] == b[i+1:]
	}
}
