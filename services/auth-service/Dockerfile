# Use Node.js LTS
FROM node:18-alpine

# Set working directory
WORKDIR /usr/src/app

# Install dependencies
COPY package*.json ./
RUN npm install --production

# Copy app source
COPY . .

# Expose the Render-assigned port
EXPOSE 3001

# Start the app
CMD ["node", "app.js"]
