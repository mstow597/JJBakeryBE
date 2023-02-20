import nodemailer from 'nodemailer';

export const sendEmail = async (options) => {
  // 1) Create a transporter - service that will send the email like gmail.
  //   Must activate the "less secure app" option in Gmail if you want to use a Gmail account.
  const transporter = nodemailer.createTransport({
    host: process.env.EMAIL_HOST,
    port: process.env.NODEMAILER_PORT,
    auth: {
      user: process.env.EMAIL_USERNAME,
      pass: process.env.EMAIL_PASSWORD,
    },
  });

  // 2) Define the email options
  const mailOptions = {
    from: `J's Bakery <dummy@dummy.io>`,
    to: options.email,
    subject: options.subject,
    text: options.message,
    html: options.html,
  };

  // 3) Send the email with nodemailer
  await transporter.sendMail(mailOptions);
};
