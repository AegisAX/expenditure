FROM node:18-alpine

# 작업 디렉토리 설정
WORKDIR /usr/src/app

# 의존성 설치
COPY package*.json ./
RUN npm install --production

# 소스 코드 복사
COPY . .

# SQLite DB 저장을 위한 디렉토리 생성
RUN mkdir -p db uploads

# 포트 노출
EXPOSE 3000

# 실행 명령
CMD ["npm", "start"]