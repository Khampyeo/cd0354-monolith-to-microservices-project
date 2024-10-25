### Build Stage
FROM node:16 AS ionic

# Install Ionic CLI globally
RUN npm install -g @ionic/cli

# Set the working directory
WORKDIR /usr/src/app

# Install app dependencies, ignoring optional dependencies
COPY package*.json ./
RUN npm install --force
# Copy app source code
COPY . .

# Build the Ionic app
RUN ionic build

### Run Stage
FROM nginx:alpine

# Copy the build output to NGINX's default HTML directory
COPY --from=ionic /usr/src/app/www /usr/share/nginx/html

# Expose the port
EXPOSE 80