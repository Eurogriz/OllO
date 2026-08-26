.PHONY: install dev test typecheck web server

install:
	npm install

dev:
	npm run dev:all

server:
	npm run dev

web:
	npm run dev:web

test:
	npm test

typecheck:
	npm run typecheck

migrate:
	npm run migrate
