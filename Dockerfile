FROM node:18-alpine
WORKDIR /app
COPY package.json yarn.lock ./
RUN yarn global add node-gyp 
RUN yarn install
COPY . .
EXPOSE 8081
CMD yarn start
