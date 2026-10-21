// NULL은 도입 전 문서의 고정 사무총장 결재선을 의미한다.
function isMiddleApprover(doc, user) {
    return doc.middleApproverEmail == null
        ? user.position === '사무총장'
        : !!doc.middleApproverEmail && doc.middleApproverEmail === user.email;
}
function canViewDocument(doc, user) {
    return user.role === 'Admin' || doc.applicantEmail === user.email
        || ['최종결재', '지급완료', '결재완료'].includes(doc.status)
        || (['제출완료', '결재중'].includes(doc.status) && isMiddleApprover(doc, user))
        || (doc.status === '결재중' && user.position === '총동문회장');
}
module.exports = { isMiddleApprover, canViewDocument };
